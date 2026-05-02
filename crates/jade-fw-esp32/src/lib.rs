#![no_std]

pub const TARGET_SOC: &str = "esp32";
pub const OFFICIAL_TARGETS: &[&str] = &["jade", "jade_v1_1"];

pub trait Esp32PlatformShim {
    fn serial_send(&mut self, bytes: &[u8]);
    fn serial_recv(&mut self, out: &mut [u8]) -> usize;
    fn monotonic_millis(&self) -> u64;
}
