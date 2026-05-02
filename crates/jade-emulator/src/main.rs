use jade_emulator::Emulator;

fn main() {
    let emulator = Emulator::new();
    let response = emulator.ping_v2("bootstrap");
    println!("{response:?}");
}
