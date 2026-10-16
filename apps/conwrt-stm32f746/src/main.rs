//! Conwrt MCU agent — STM32F746G-DISCO (#215 slice 4).
//!
//! The Ethernet-attached agent: TCP (embassy-net + the onboard LAN8742)
//! as the controller transport, USART6 (Arduino D1/D0 = PC6/PC7) as the
//! router console passthrough. Both drive one [`ServerCore`] through
//! [`agent_session_stream_events`] — controller frames and live UART RX
//! selected against each other, events flowing to the controller as they
//! arrive, so a passively listening controller sees the switch's boot
//! output without sending anything.
//!
//! Bench wiring (32F746G-DISCO ↔ GS1900-8HP): DISCO RJ45 → switch port 8
//! (PoE DISABLED first — the DISCO PHY is not PoE-tolerant); switch
//! console TX → D0 (PC7), RX → D1 (PC6), GND → GND; console VCC never
//! connected. Static IPv4, compile-time constants below — set them to
//! the assigned bench DUT VLAN before flashing.
//!
//! This slice runs the TCP session as the sole [`ServerCore`] owner
//! (single-owner sessions; USB-CDC stays available on the F469 sibling
//! app and can return here behind a shared-session slice if the bench
//! ever needs both wires at once). defmt-RTT over the ST-LINK is the
//! out-of-band log door.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use defmt_rtt as _;
use embassy_executor::{Spawner, task};
use embassy_net::tcp::TcpSocket;
use embassy_net::{Ipv4Address, Stack, StackResources, StaticConfigV4};
use embassy_stm32::eth::{self, PacketQueue};
use embassy_stm32::time::Hertz;
use embassy_stm32::usart::{BufferedUart, BufferedUartRx, BufferedUartTx, Config as UartConfig};
use embassy_stm32::{Config as ChipConfig, Peripherals, bind_interrupts, peripherals, rcc, usart};
use panic_probe as _;
use static_cell::StaticCell;

use conwrt_agent_io::{EventSource, agent_session_stream_events};
use conwrt_agent_proto::dispatch::WireError;
use conwrt_agent_proto::protocol::CapabilityInfo;
use conwrt_agent_proto::server::{ServerCore, UartSink};

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    USART6 => usart::BufferedInterruptHandler<peripherals::USART6>;
});

/// Locally administered, firmware-stable (a per-boot random MAC would
/// poison the controller's ARP cache).
const AGENT_MAC: [u8; 6] = [0x02, 0x43, 0x57, 0x46, 0x37, 0x34];

/// Bench DUT VLAN address — set to the assigned bay VLAN before flashing.
const AGENT_IPV4: Ipv4Address = Ipv4Address::new(192, 168, 104, 2);
const AGENT_GW: Ipv4Address = Ipv4Address::new(192, 168, 104, 1);

/// The agent's TCP port (the HIL mock's conventional port).
const AGENT_PORT: u16 = 8400;

/// Router console: OpenWrt GS1900 console default.
const UART_BAUD: u32 = 115_200;

/// Heap size for the [`HEAP`] allocator (protocol Vec allocations), in
/// internal SRAM — the DISCO's SDRAM (FMC) stays untouched.
const HEAP_SIZE: usize = 32 * 1024;

#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();

static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
    [core::mem::MaybeUninit::uninit(); HEAP_SIZE];

static ETH_QUEUE: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
static NET_RESOURCES: StaticCell<StackResources<2>> = StaticCell::new();
static UART_TX_RING: StaticCell<[u8; 1024]> = StaticCell::new();
static UART_RX_RING: StaticCell<[u8; 1024]> = StaticCell::new();
static TCP_TX_BUF: StaticCell<[u8; 4096]> = StaticCell::new();
static TCP_RX_BUF: StaticCell<[u8; 4096]> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    unsafe {
        HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE);
    }

    let p: Peripherals = embassy_stm32::init(agent_clock_config());
    defmt::info!("conwrt-stm32f746 agent up");

    let uart = BufferedUart::new(
        p.USART6,
        p.PC7,
        p.PC6,
        UART_TX_RING.uninit().write([0u8; 1024]),
        UART_RX_RING.uninit().write([0u8; 1024]),
        Irqs,
        uart_config(),
    )
    .expect("USART6 config");
    let (uart_tx, uart_rx) = uart.split();

    let device = embassy_stm32::eth::Ethernet::new(
        ETH_QUEUE.uninit().write(PacketQueue::new()),
        p.ETH,
        Irqs,
        p.PA1,
        p.PA7,
        p.PC4,
        p.PC5,
        p.PG13,
        p.PG14,
        p.PG11,
        AGENT_MAC,
        p.ETH_SMA,
        p.PA2,
        p.PC1,
    );
    let config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: embassy_net::Ipv4Cidr::new(AGENT_IPV4, 24),
        gateway: Some(AGENT_GW),
        dns_servers: heapless::Vec::new(),
    });
    let (stack, runner) = embassy_net::new(
        device,
        config,
        NET_RESOURCES.uninit().write(StackResources::new()),
        0x846_f746_02,
    );
    spawner.spawn(net_task(runner).expect("spawn net"));

    let server = ServerCore::with_uart(
        "conwrt-stm32f746 0.2.0",
        capabilities(),
        Box::new(Usart6Sink { tx: uart_tx }),
    );
    spawner.spawn(agent_task(stack, server, UartRxSource(uart_rx)).expect("spawn agent"));
}

type EthDevice = embassy_stm32::eth::Ethernet<
    'static,
    peripherals::ETH,
    embassy_stm32::eth::GenericPhy<embassy_stm32::eth::Sma<'static, peripherals::ETH_SMA>>,
>;

#[task]
async fn net_task(mut runner: embassy_net::Runner<'static, EthDevice>) {
    runner.run().await
}

#[task]
async fn agent_task(stack: Stack<'static>, mut server: ServerCore, mut uart_rx: UartRxSource) {
    // One socket, reused per connection (StaticCell buffers init once;
    // abort() returns it to Closed and accept() listens again).
    let mut socket = TcpSocket::new(
        stack,
        TCP_TX_BUF.uninit().write([0u8; 4096]),
        TCP_RX_BUF.uninit().write([0u8; 4096]),
    );
    loop {
        if socket
            .accept((Ipv4Address::UNSPECIFIED, AGENT_PORT))
            .await
            .is_err()
        {
            continue;
        }
        defmt::info!("controller connected (tcp)");
        server.reset_session();
        agent_session_stream_events(&mut socket, &mut uart_rx, &mut server).await;
        defmt::info!("controller disconnected — leases expired");
        socket.abort();
    }
}

/// USART6 RX half as the agent's event source (newtype: orphan rule).
struct UartRxSource(BufferedUartRx<'static>);

impl EventSource for UartRxSource {
    type Error = usart::Error;

    async fn wait_data(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        embedded_io_async::Read::read(&mut self.0, buf).await
    }
}

/// USART6 TX half as the lease-gated UART sink. Blocking write into the
/// ring buffer (usually a memcpy); console lines are short.
struct Usart6Sink {
    tx: BufferedUartTx<'static>,
}

impl UartSink for Usart6Sink {
    fn uart_write(&mut self, port: u8, data: &[u8]) -> Result<usize, WireError> {
        if port != 0 {
            return Err(WireError::Internal(String::from("uart1 does not exist")));
        }
        embedded_io::Write::write(&mut self.tx, data)
            .map_err(|_| WireError::Internal(String::from("usart6 write failed")))
    }
}

fn uart_config() -> UartConfig {
    let mut config = UartConfig::default();
    config.baudrate = UART_BAUD;
    config
}

fn capabilities() -> Vec<CapabilityInfo> {
    Vec::from([
        CapabilityInfo {
            name: String::from("serial"),
            detail: Vec::from([(String::from("uarts"), String::from("1"))]),
        },
        CapabilityInfo {
            name: String::from("diag"),
            detail: Vec::from([
                (String::from("chip"), String::from("stm32f746ng")),
                (String::from("fw"), String::from("conwrt-stm32f746 0.2.0")),
                (String::from("heap_bytes"), String::from("32768")),
            ]),
        },
    ])
}

/// HSE 8 MHz crystal → PLL1: 168 MHz sysclk, 48 MHz on PLL1_Q (the same
/// integer PLL math as the F469 BSP config; RMII ref clock is external
/// from the LAN8742 on PA1 and needs no RCC change).
fn agent_clock_config() -> ChipConfig {
    let mut config = ChipConfig::default();
    config.rcc.hse = Some(rcc::Hse {
        freq: Hertz(8_000_000),
        mode: rcc::HseMode::Oscillator,
    });
    config.rcc.pll_src = rcc::PllSource::HSE;
    config.rcc.pll = Some(rcc::Pll {
        prediv: rcc::PllPreDiv::DIV4,
        mul: rcc::PllMul::MUL168,
        divp: Some(rcc::PllPDiv::DIV2),
        divq: Some(rcc::PllQDiv::DIV7),
        divr: None,
    });
    config.rcc.ahb_pre = rcc::AHBPrescaler::DIV1;
    config.rcc.apb1_pre = rcc::APBPrescaler::DIV4;
    config.rcc.apb2_pre = rcc::APBPrescaler::DIV2;
    config.rcc.sys = rcc::Sysclk::PLL1_P;
    config.rcc.mux.clk48sel = rcc::mux::Clk48sel::PLL1_Q;
    config
}
