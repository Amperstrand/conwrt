//! Conwrt MCU agent — STM32F469I-DISCO (M5, issue #110).
//!
//! USB CDC-ACM is the transport (ADR-0004's second wire); COBS frames
//! carry the shared Tier-A protocol ([`conwrt_agent_proto`]); the agent
//! logic itself is [`ServerCore`] — identical semantics to the std TCP
//! agent. This slice advertises capabilities and serves the
//! handshake/lease protocol; the UART passthrough capability lands next
//! (USART6 on PG14/PG9).
//!
//! Connection lifecycle drives lease lifecycle: a dropped CDC connection
//! (host unplug, port close) resets the session and expires every lease
//! (`Abort` default; `Complete` parking is an M6 concern).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_stm32::time::Hertz;
use embassy_stm32::usb::{self, Driver, Instance};
use embassy_stm32::{Config as ChipConfig, Peripherals, bind_interrupts, peripherals, rcc};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcState};
use embassy_usb::{Builder as UsbBuilder, Config as UsbDevConfig};
use panic_probe as _;

use conwrt_agent_io::{CDC_FS_PACKET, agent_session};
use conwrt_agent_proto::protocol::CapabilityInfo;
use conwrt_agent_proto::server::ServerCore;

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
});

/// Heap size for the [`HEAP`] allocator (protocol Vec allocations).
const HEAP_SIZE: usize = 32 * 1024;

#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();

static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
    [core::mem::MaybeUninit::uninit(); HEAP_SIZE];

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    unsafe {
        HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE);
    }

    let p: Peripherals = embassy_stm32::init(usb_clock_config());
    defmt::info!("conwrt-stm32 agent up");

    let mut server = ServerCore::new(
        "conwrt-stm32 0.1.0",
        Vec::from([CapabilityInfo {
            name: String::from("serial"),
            detail: Vec::from([(String::from("uarts"), String::from("1"))]),
        }]),
    );

    let mut ep_out_buffer = [0u8; 256];
    let mut usb_cfg = usb::Config::default();
    // The DISCO's CN13 has no VBUS sense line wired to the MCU.
    usb_cfg.vbus_detection = false;
    let driver = Driver::new_fs(
        p.USB_OTG_FS,
        Irqs,
        p.PA12,
        p.PA11,
        &mut ep_out_buffer,
        usb_cfg,
    );

    let mut dev_cfg = UsbDevConfig::new(0xc0de, 0xcafe);
    dev_cfg.manufacturer = Some("Amperstrand");
    dev_cfg.product = Some("conwrt agent");
    // Per-board USB serial from the MCU's 96-bit device ID (#377): a
    // hardcoded serial collides /dev/serial/by-id across identical
    // units (AGENTS.md specimen identity; the esp32s3 app's pattern).
    let serial = alloc::format!("f469i-disco-{}", embassy_stm32::uid::uid_hex());
    dev_cfg.serial_number = Some(&serial);

    let mut config_descriptor = [0u8; 256];
    let mut bos_descriptor = [0u8; 256];
    let mut control_buf = [0u8; 64];
    let mut state = CdcState::new();

    let mut builder = UsbBuilder::new(
        driver,
        dev_cfg,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut [], // no MS OS descriptor
        &mut control_buf,
    );
    let mut class = CdcAcmClass::new(&mut builder, &mut state, CDC_FS_PACKET as u16);
    let mut usb = builder.build();

    let usb_fut = usb.run();
    let agent_fut = session_loop(&mut class, &mut server);
    embassy_futures::join::join(usb_fut, agent_fut).await;
}

/// HSE 8 MHz crystal → PLL1: 168 MHz sysclk, 48 MHz on PLL1_Q for USB
/// (the BSP's proven `config_usb_only` clocks for this board).
fn usb_clock_config() -> ChipConfig {
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

async fn session_loop<'d, T: Instance + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T>>,
    server: &mut ServerCore,
) {
    loop {
        class.wait_connection().await;
        defmt::info!("controller connected");
        server.reset_session();
        agent_session(class, server, CDC_FS_PACKET).await;
        defmt::info!("controller disconnected — leases expired");
    }
}
