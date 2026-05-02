#![no_std]

pub const TARGET_SOC: &str = "esp32s3";
pub const OFFICIAL_TARGETS: &[&str] = &["jade_v2", "jade_v2c"];

pub trait Esp32s3PlatformShim {
    fn serial_send(&mut self, bytes: &[u8]);
    fn serial_recv(&mut self, out: &mut [u8]) -> usize;
    fn monotonic_millis(&self) -> u64;
    fn hardware_attestation_available(&self) -> bool;
}
