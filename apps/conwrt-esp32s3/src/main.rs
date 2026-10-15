//! Conwrt MCU agent — ESP32-S3 (M5, issue #111).
//!
//! USB-CDC is the first wire (the S3's native USB OTG, ADR-0004's second
//! transport); COBS frames carry the shared Tier-A protocol
//! ([`conwrt_agent_proto`]); the agent logic itself is [`ServerCore`] —
//! identical semantics to the std TCP agent and the STM32 firmware (#110).
//! This slice serves the handshake + a read-only `diag` capability
//! (chip identity, firmware version, heap size). Wi-Fi/Ethernet waits on
//! esp-radio (beta) — tracked in #111, out of this scaffold.
//!
//! Connection lifecycle drives lease lifecycle: a dropped CDC connection
//! (host unplug, port close) resets the session and expires every lease
//! (`Abort` default), exactly like the STM32 firmware.
//!
//! Toolchain: Xtensa builds require the esp-rs fork (`cargo +esp`), pinned
//! 1.98.1.0 — decision, evidence, and CI strategy in ADR-0012.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_usb::Builder as UsbBuilder;
use embassy_usb::Config as UsbDevConfig;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcState};
use esp_backtrace as _;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::usb::otg::Usb;
use esp_hal::usb::otg::embassy_usb_device::{Config as OtgConfig, Driver};

use conwrt_agent_proto::cobs::{CobsPump, encode_frame as cobs_encode};
use conwrt_agent_proto::dispatch;
use conwrt_agent_proto::protocol::CapabilityInfo;
use conwrt_agent_proto::server::ServerCore;

esp_bootloader_esp_idf::esp_app_desc!();

/// CDC bulk max packet size (full speed).
const CDC_PACKET: usize = 64;

/// Dram heap for protocol Vec/String allocations (esp-alloc static region).
const HEAP_SIZE: usize = 48 * 1024;

#[esp_hal::main]
async fn main(_spawner: Spawner) {
    esp_alloc::heap_allocator!(size: HEAP_SIZE);

    esp_println::println!("conwrt-esp32s3 agent up");

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let mut server = ServerCore::new("conwrt-esp32s3 0.1.0", Vec::from([diag_capability()]));

    // S3 native USB OTG: DP = GPIO20, DM = GPIO19 (devkit wiring).
    let usb = Usb::new_fs(peripherals.USB_FS, peripherals.GPIO20, peripherals.GPIO19);
    let mut ep_out_buffer = [0u8; 1024];
    // Bench units are bus-powered off the agent port: no VBUS sense needed
    // (default false), same assumption as the STM32 disco transport.
    let driver = Driver::new(usb, &mut ep_out_buffer, OtgConfig::default());

    let mut dev_cfg = UsbDevConfig::new(0xc0de, 0xcafe);
    dev_cfg.manufacturer = Some("Amperstrand");
    dev_cfg.product = Some("conwrt agent");
    // Per-board USB serial from the eFuse base MAC: two S3 agents on one
    // host must enumerate as distinct ttyACM specimens (stable by-id paths),
    // never a shared hardcoded identity.
    let serial = alloc::format!("conwrt-{}", esp_hal::efuse::base_mac_address());
    esp_println::println!("usb serial: {serial}");
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
    let mut class = CdcAcmClass::new(&mut builder, &mut state, CDC_PACKET as u16);
    let mut usb = builder.build();

    let usb_fut = usb.run();
    let agent_fut = session_loop(&mut class, &mut server);
    join(usb_fut, agent_fut).await;
}

/// The read-only diagnostic capability the S3 serves (#111 acceptance):
/// chip identity, firmware version, and the configured heap size, carried
/// in the capability advertisement — no lease, no protocol addition.
fn diag_capability() -> CapabilityInfo {
    let heap = esp_alloc::HEAP.stats();
    CapabilityInfo {
        name: String::from("diag"),
        detail: Vec::from([
            (String::from("chip"), String::from("esp32s3")),
            (String::from("fw"), String::from("conwrt-esp32s3 0.1.0")),
            (String::from("heap_bytes"), heap.size.to_string()),
        ]),
    }
}

async fn session_loop<'d>(class: &mut CdcAcmClass<'d, Driver<'d>>, server: &mut ServerCore) {
    let mut buf = [0u8; CDC_PACKET];
    loop {
        class.wait_connection().await;
        esp_println::println!("controller connected");
        server.reset_session();
        let mut pump = CobsPump::new();
        while let Ok(n) = class.read_packet(&mut buf).await {
            pump.feed(&buf[..n]);
            while let Some(frame) = pump.pop_frame() {
                let Some(response) = dispatch::decode_frame(&frame)
                    .ok()
                    .and_then(|decoded| server.handle_frame(decoded))
                else {
                    continue;
                };
                if let Ok(bytes) = dispatch::encode_frame(&response) {
                    write_cdc(class, &cobs_encode(&bytes)).await;
                }
            }
        }
        esp_println::println!("controller disconnected — leases expired");
    }
}

/// CDC bulk writes are packet-sized: chunk the frame and append a
/// zero-length packet when it ends exactly on a packet boundary (the host
/// cannot tell "done" from "more coming" otherwise).
async fn write_cdc<'d>(class: &mut CdcAcmClass<'d, Driver<'d>>, data: &[u8]) {
    for chunk in data.chunks(CDC_PACKET) {
        if class.write_packet(chunk).await.is_err() {
            return;
        }
    }
    if !data.is_empty() && data.len().is_multiple_of(CDC_PACKET) {
        let _ = class.write_packet(&[]).await;
    }
}
