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
use embassy_stm32::usart::BufferedUartRx;
use embassy_stm32::usart::{BufferedUart, BufferedUartTx, Config as UartConfig};
use embassy_stm32::{Config as ChipConfig, Peripherals, bind_interrupts, peripherals, rcc, usart};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use embassy_sync::mutex::Mutex;
use panic_probe as _;
use static_cell::StaticCell;

use conwrt_agent_io::{EventSource, agent_session_stream_events};
use conwrt_agent_proto::dispatch::WireError;
use conwrt_agent_proto::protocol::{CapabilityInfo, StreamAck, StreamChunk};
use conwrt_agent_proto::server::{ServerCore, TransferSink, UartSink};
use conwrt_executor::{ExecutorTransfer, PostPump, PumpStep, TcpHttpIo};

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    USART6 => usart::BufferedInterruptHandler<peripherals::USART6>;
});

/// Locally administered, firmware-stable (a per-boot random MAC would
/// poison the controller's ARP cache).
const AGENT_MAC: [u8; 6] = [0x02, 0x43, 0x57, 0x46, 0x37, 0x34];

/// Bench DUT VLAN address. Species-level placeholder only: resolve the
/// actual bay VLAN/address/gateway from the lab registry and set them at
/// BUILD TIME without editing source — `CONWRT_AGENT_IPV4` /
/// `CONWRT_AGENT_GW` (`a.b.c.d`) — e.g. for the gs108t flat recovery
/// segment: `CONWRT_AGENT_IPV4=192.168.0.2 CONWRT_AGENT_GW=192.168.0.1
/// cargo build --release` (AGENTS.md: never hardcode bench IPs — the
/// bench DUT-bay convention is VLAN 100N, 192.168.100N.0/24).
const AGENT_IPV4_DEFAULT: &str = "192.168.100.2";
const AGENT_GW_DEFAULT: &str = "192.168.100.1";

fn agent_ipv4() -> Ipv4Address {
    seat_ipv4(
        "CONWRT_AGENT_IPV4",
        option_env!("CONWRT_AGENT_IPV4"),
        AGENT_IPV4_DEFAULT,
    )
}

fn agent_gateway() -> Ipv4Address {
    seat_ipv4(
        "CONWRT_AGENT_GW",
        option_env!("CONWRT_AGENT_GW"),
        AGENT_GW_DEFAULT,
    )
}

/// Parse `a.b.c.d`, falling back to the default with a defmt warning —
/// a typo'd build-time seat override must warn, never brick the boot.
fn seat_ipv4(env_name: &str, value: Option<&'static str>, default: &'static str) -> Ipv4Address {
    let text = value.unwrap_or(default);
    let mut octets = [0u8; 4];
    let mut ok = true;
    for (i, part) in text.split('.').enumerate() {
        match (i < 4, part.parse::<u8>()) {
            (true, Ok(o)) => octets[i] = o,
            _ => {
                ok = false;
                break;
            }
        }
    }
    if !ok {
        defmt::warn!(
            "{=str}={=str} is not a.b.c.d; using {=str}",
            env_name,
            text,
            default
        );
        return parse_default(default);
    }
    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
}

fn parse_default(default: &'static str) -> Ipv4Address {
    let mut octets = [0u8; 4];
    for (i, part) in default.split('.').enumerate() {
        octets[i] = part.parse().expect("compile-time default is a.b.c.d");
    }
    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
}

/// The agent's TCP port (the HIL mock's conventional port).
const AGENT_PORT: u16 = 8400;

/// Router console: OpenWrt GS1900 console default.
const UART_BAUD: u32 = 115_200;

/// Executor transfer window (undrained bytes) — the #226 firmware
/// profile; heap-allocated at first chunk, so no static footprint.
const EXECUTOR_WINDOW: usize = 8 * 1024;

/// The recovery POST target — one router in U-Boot recovery on the
/// agent's own segment. Species-level default (the D-Link recovery
/// LAN); override at BUILD TIME per seat: `CONWRT_RECOVERY_TARGET`
/// (`a.b.c.d`), same rules as the agent address above.
const RECOVERY_TARGET_DEFAULT: &str = "192.168.0.1";
const RECOVERY_ENDPOINT: &str = "/upload";
const RECOVERY_PORT: u16 = 80;
/// Any WebKit-shaped token is wire-equivalent (the server delimits, it
/// does not parse); no cheap randomness on no_std, so it is fixed.
const RECOVERY_BOUNDARY: &str = "----WebKitFormBoundary7460a1b2c3d4e5f6";

fn recovery_target() -> Ipv4Address {
    seat_ipv4(
        "CONWRT_RECOVERY_TARGET",
        option_env!("CONWRT_RECOVERY_TARGET"),
        RECOVERY_TARGET_DEFAULT,
    )
}

/// One shared executor window: the dispatch sink (sync, from the
/// controller session) and the pump task (async) lock the same
/// [`ExecutorTransfer`]. StaticCell because [`ExecutorTransfer::new`]
/// is not const.
static EXECUTOR: StaticCell<Mutex<CriticalSectionRawMutex, ExecutorTransfer>> = StaticCell::new();

/// Pump socket buffers — 2 KiB each (+4 KiB bss over #237; the write
/// side streams multipart chunks, the read side only carries the tiny
/// verdict page, bounded at 8 KiB by `MAX_VERDICT_BYTES`).
static PUMP_TX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
static PUMP_RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();

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

/// Console chunks: uart task → agent session. Bounded; drops when no
/// controller is connected (RTT already recorded every chunk).
static CONSOLE_CH: Channel<CriticalSectionRawMutex, Vec<u8>, 16> = Channel::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    unsafe {
        HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE);
    }

    let p: Peripherals = embassy_stm32::init(agent_clock_config());
    let uid = embassy_stm32::uid::uid_hex();
    defmt::info!("conwrt-stm32f746 agent up (uid={})", uid);

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
        address: embassy_net::Ipv4Cidr::new(agent_ipv4(), 24),
        gateway: Some(agent_gateway()),
        dns_servers: heapless::Vec::new(),
    });
    let (stack, runner) = embassy_net::new(
        device,
        config,
        NET_RESOURCES.uninit().write(StackResources::new()),
        // embassy net seed spells 846-F746-02 (the SoC) — grouping kept
        // intentionally; not a size/addr literal (#298)
        #[allow(clippy::unusual_byte_groupings)]
        0x846_f746_02,
    );
    spawner.spawn(net_task(runner).expect("spawn net"));

    // One executor window, shared: the dispatch sink writes chunks
    // (controller session task), the pump task drains them to the
    // recovery POST (#226 wiring slice).
    let executor = EXECUTOR.init(Mutex::new(ExecutorTransfer::new(EXECUTOR_WINDOW)));

    let server = ServerCore::with_uart(
        "conwrt-stm32f746 0.5.0",
        capabilities(),
        Box::new(Usart6Sink { tx: uart_tx }),
    )
    // #226: StreamChunk/StreamStatus land in the shared executor
    // window; the pump task below drains it into the recovery POST —
    // one attempt per transfer id, bench-gated target profile.
    .attach_transfer(Box::new(SharedWindow(executor)))
    // #215 slice 5: standalone detect mode — the router console RX
    // (already feeding UartData events) runs through the shared
    // probe-core milestone tracker; a controller arms it with
    // DetectStart and harvests DetectFinding events (mock-first in
    // conwrt-agent-proto's HIL suite; bench validation NEEDS-BENCH).
    .attach_detect(0);
    spawner.spawn(uart_task(uart_rx, CONSOLE_CH.sender()).expect("spawn uart"));
    spawner.spawn(
        agent_task(stack, server, ConsoleSource(CONSOLE_CH.receiver())).expect("spawn agent"),
    );
    spawner.spawn(pump_task(stack, executor).expect("spawn pump"));
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
async fn agent_task(stack: Stack<'static>, mut server: ServerCore, mut uart_rx: ConsoleSource) {
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

/// Dispatch-side door into the shared [`ExecutorTransfer`] — the
/// controller session's `ServerCore` calls these synchronously. The
/// pump task holds the async lock only around one `step` at a time;
/// a chunk arriving mid-step (wire backpressure) sees `window busy`
/// — the same retryable Internal class as `window full`.
struct SharedWindow(&'static Mutex<CriticalSectionRawMutex, ExecutorTransfer>);

impl TransferSink for SharedWindow {
    fn stream_chunk(&mut self, chunk: &StreamChunk) -> Result<StreamAck, WireError> {
        self.0
            .try_lock()
            .ok()
            .ok_or_else(|| WireError::Internal(String::from("window busy: pump mid-step")))
            .and_then(|mut w| w.stream_chunk(chunk))
    }
    fn stream_status(&mut self, transfer_id: u64) -> Result<StreamAck, WireError> {
        self.0
            .try_lock()
            .ok()
            .ok_or_else(|| WireError::Internal(String::from("window busy: pump mid-step")))
            .and_then(|mut w| w.stream_status(transfer_id))
    }
}

/// The recovery POST task (#226 wiring slice): one wire attempt per
/// transfer id. A fresh [`PostPump`] per connection; the verdict (or
/// the failure) is logged to RTT — the controller observes the same
/// outcome through the transfer's ack progression and can re-feed
/// under a new id (the `WrongTransfer` reset) for a fresh attempt.
#[task]
async fn pump_task(
    stack: Stack<'static>,
    window: &'static Mutex<CriticalSectionRawMutex, ExecutorTransfer>,
) {
    let target = recovery_target();
    let mut socket = TcpSocket::new(
        stack,
        PUMP_TX_BUF.uninit().write([0u8; 2048]),
        PUMP_RX_BUF.uninit().write([0u8; 2048]),
    );
    // Bounded lock holds (#452 review rounds 2-3): pump.step awaits
    // wire writes while holding the window mutex; without a timeout a
    // dead peer with a full buffer would hold it FOREVER — every
    // controller chunk would see 'window busy' with no recovery. 40 s
    // covers the model-documented 30 s flash-response pause
    // (dlink-covr-x1860-a1.json flash_response_delay_seconds — the
    // server writes flash before answering) while still bounding every
    // pump-side await (connect included) so 'window busy' stays
    // transient.
    socket.set_timeout(Some(embassy_time::Duration::from_secs(40)));
    // The id this task last spent a wire attempt on: a completed or
    // failed POST is never retried for the same id (the one-request
    // window is spent); a NEW id (fresh controller feed) re-arms.
    let mut attempted: Option<u64> = None;
    loop {
        let bound = window.lock().await.transfer_id();
        let Some(id) = bound else {
            attempted = None;
            embassy_time::Timer::after(embassy_time::Duration::from_millis(200)).await;
            continue;
        };
        if attempted == Some(id) {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(200)).await;
            continue;
        }
        if socket.connect((target, RECOVERY_PORT)).await.is_err() {
            socket.abort();
            embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
            continue;
        }
        defmt::info!("recovery: connected, pumping transfer {}", id);
        let mut io = TcpHttpIo::new(socket);
        let mut pump = PostPump::new("192.168.0.1", RECOVERY_ENDPOINT, RECOVERY_BOUNDARY);
        loop {
            match pump.step(&mut io, window.lock().await.window()).await {
                Ok(PumpStep::Posted(outcome)) => {
                    let verdict = match outcome.verdict {
                        conwrt_executor::Verdict::Accepted => "accepted",
                        conwrt_executor::Verdict::AcceptedHtml => "accepted-html",
                        conwrt_executor::Verdict::Rejected { .. } => "rejected",
                        conwrt_executor::Verdict::NoResponse => "no-response",
                    };
                    defmt::info!(
                        "recovery verdict: {=str} ({} bytes uploaded)",
                        verdict,
                        outcome.uploaded
                    );
                    break;
                }
                Ok(PumpStep::Superseded) => {
                    defmt::warn!("recovery: window superseded mid-POST — attempt spent");
                    break;
                }
                Ok(PumpStep::Streaming { drained }) => {
                    if drained == 0 {
                        // window empty, more chunks expected — yield
                        embassy_time::Timer::after(embassy_time::Duration::from_millis(20)).await;
                    }
                }
                Ok(PumpStep::Idle) => {
                    // window vanished between gate and step (reset):
                    // re-evaluate on the next outer loop
                    break;
                }
                Err(e) => {
                    defmt::warn!("recovery pump failed: {}", pump_error_str(&e));
                    break;
                }
            }
        }
        socket = io.into_inner();
        socket.abort();
        // Record the id the pump ACTUALLY served: the window may have
        // re-targeted while the connection was pending — marking the
        // stale pre-connect id would retry the freshly-posted one and
        // burn a second recovery window (#452 review round 1).
        let served = pump.bound_id().unwrap_or(id);
        if served != id {
            defmt::warn!(
                "recovery: window re-targeted {} -> {} mid-connect",
                id,
                served
            );
        }
        attempted = Some(served);
    }
}

/// defmt needs its own format types — map [`PostError`] to a static
/// string (the stage names carry the diagnostic; RTT is not a debugger).
fn pump_error_str(e: &conwrt_executor::PostError) -> &'static str {
    match e {
        conwrt_executor::PostError::Write { op } => match *op {
            "head" => "write:head",
            "footer" => "write:footer",
            _ => "write:body",
        },
        conwrt_executor::PostError::Read => "read",
        conwrt_executor::PostError::Incomplete { .. } => "incomplete",
        conwrt_executor::PostError::NoTotal => "no-total",
        conwrt_executor::PostError::FramingOverflow => "framing-overflow",
        conwrt_executor::PostError::AlreadyStarted => "already-started",
        conwrt_executor::PostError::NotStarted => "not-started",
        conwrt_executor::PostError::SizeMismatch { .. } => "size-mismatch",
    }
}

/// Always-on console reader — independent of any TCP connection, so a
/// boot banner is captured (to RTT and the channel) even while the
/// network is down or no controller is attached. This is the flight
/// recorder for the switch's self-reboot quirk.
#[task]
async fn uart_task(
    mut rx: BufferedUartRx<'static>,
    console: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 16>,
) {
    let mut buf = [0u8; 64];
    loop {
        match embedded_io_async::Read::read(&mut rx, &mut buf).await {
            Ok(0) | Err(_) => {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await
            }
            Ok(n) => {
                defmt::info!("console: {=[u8]:a}", &buf[..n]);
                let _ = console.try_send(Vec::from(&buf[..n]));
            }
        }
    }
}

/// Console channel receive end as the agent's event source (newtype:
/// orphan rule). Never yields Ok(0) — the session ends only via the
/// stream side.
struct ConsoleSource(Receiver<'static, CriticalSectionRawMutex, Vec<u8>, 16>);

impl EventSource for ConsoleSource {
    type Error = core::convert::Infallible;

    async fn wait_data(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let chunk = self.0.receive().await;
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        Ok(n)
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
    // Per-unit identity from the MCU's 96-bit device ID (the esp32s3
    // app's per-board serial pattern): identical units on one bench
    // stay distinguishable to controllers (#377, AGENTS.md specimen
    // identity).
    let uid = embassy_stm32::uid::uid_hex();
    Vec::from([
        CapabilityInfo {
            name: String::from("serial"),
            detail: Vec::from([(String::from("uarts"), String::from("1"))]),
        },
        CapabilityInfo {
            name: String::from("executor"),
            detail: Vec::from([
                (String::from("window_bytes"), String::from("8192")),
                (
                    String::from("wire"),
                    // #226 wiring slice: the pump task drains the
                    // window into the recovery POST (one attempt per
                    // transfer id; verdict on RTT). Target = build-time
                    // CONWRT_RECOVERY_TARGET (default the D-Link
                    // recovery LAN); the controller just streams. The
                    // path is wired but NOT yet live-validated — the
                    // bench leg (gated) is that validation.
                    String::from("full-bench-pending"),
                ),
            ]),
        },
        CapabilityInfo {
            name: String::from("diag"),
            detail: Vec::from([
                (String::from("chip"), String::from("stm32f746ng")),
                (String::from("fw"), String::from("conwrt-stm32f746 0.5.0")),
                (String::from("heap_bytes"), String::from("32768")),
                (String::from("uid"), String::from(uid)),
            ]),
        },
        CapabilityInfo {
            // #215 slice 5: standalone detect mode — boot-milestone
            // detection on uart0 (DetectStart/DetectStatus/DetectFinding),
            // powered by the shared conwrt-probe-core tracker.
            name: String::from("detect"),
            detail: Vec::from([
                (String::from("port"), String::from("0")),
                (
                    String::from("milestones"),
                    String::from(
                        "serial_uboot_banner,serial_kernel_start,serial_procd_preinit,\
                         serial_procd_init,serial_login_prompt",
                    ),
                ),
                (String::from("core"), String::from("conwrt-probe-core")),
            ]),
        },
    ])
}

/// The 32F746G-DISCO's 25 MHz HSE crystal → PLL1: 168 MHz sysclk,
/// 48 MHz on PLL1_Q (25/25 = 1 MHz in, ×336 = 336 MHz VCO, /2 and /7).
/// The F469 sibling board's 8 MHz dividers here would drive the VCO to
/// 1.05 GHz — sysclk 525 MHz, clk48 150 MHz: out of spec, CDC dead.
/// RMII ref clock is external from the LAN8742 on PA1 and needs no RCC
/// change.
fn agent_clock_config() -> ChipConfig {
    let mut config = ChipConfig::default();
    config.rcc.hse = Some(rcc::Hse {
        freq: Hertz(25_000_000),
        mode: rcc::HseMode::Oscillator,
    });
    config.rcc.pll_src = rcc::PllSource::HSE;
    config.rcc.pll = Some(rcc::Pll {
        prediv: rcc::PllPreDiv::DIV25,
        mul: rcc::PllMul::MUL336,
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
