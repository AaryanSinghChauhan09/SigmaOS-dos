//! SigmaOS component binary: dos

use sigmaos_dos::Component;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Component::new().operate()?;
    println!("sigmaos-dos: ok");
    Ok(())
}
