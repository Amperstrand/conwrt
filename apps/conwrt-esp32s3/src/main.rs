//! Conwrt MCU agent — ESP32-S3 (M5, issue #111).
//!
//! USB-CDC is the first wire (the S3's native USB OTG, ADR-0004's second
//! transport); COBS frames carry the shared Tier-A protocol
//! ([`conwrt_agent_proto`]); the agent logic itself is [`ServerCore`] —
//! identical semantics to the std TCP agent and the STM32 firmware (#110).
//!
//! This slice brings up the board: esp-hal 1.2 + esp-rtos (embassy runtime)
//! and a heartbeat on the console. The USB-CDC transport and the diagnostic
//! capability land in the next slices. Wi-Fi/Ethernet waits on esp-radio
//! (beta) — tracked in #111, deliberately out of this scaffold.
//!
//! Toolchain: Xtensa builds require the esp-rs fork (`cargo +esp`), pinned
//! 1.98.1.0 — decision, evidence, and CI strategy in ADR-0012.

#![no_std]
#![no_main]

use embassy_executor::Spawner;
use esp_backtrace as _;
use esp_hal::timer::timg::TimerGroup;

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal::main]
async fn main(_spawner: Spawner) {
    esp_println::println!("conwrt-esp32s3 agent up");

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    loop {
        embassy_time::Timer::after_secs(1).await;
        esp_println::println!("tick");
    }
}
