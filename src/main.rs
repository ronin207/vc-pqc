#[cfg(feature = "std")]
use vc_pqc::{keygen_with_params, loquat_setup, loquat_sign, loquat_verify, LoquatResult};

#[cfg(feature = "std")]
fn main() -> LoquatResult<()> {
    println!("Running Loquat signature scheme example...");

    // 1. Setup
    println!("Generating public parameters for 128-bit security...");
    let params = loquat_setup(128)?;
    println!("Setup complete.");

    // 2. Key Generation
    println!("Generating key pair...");
    let keypair = keygen_with_params(&params)?;
    println!("Key pair generated.");

    // 3. Signing
    let message = b"This is a test message for the Loquat signature scheme.";
    println!(
        "\nSigning message: \"{}\"",
        std::str::from_utf8(message).unwrap()
    );
    let signature = loquat_sign(message, &keypair, &params)?;
    println!("Signature generated successfully.");

    // 4. Verification
    println!("\nVerifying signature...");
    let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)?;

    if is_valid {
        println!("\nSUCCESS: Signature is valid!");
    } else {
        println!("\nFAILURE: Signature is NOT valid!");
    }

    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() {
    panic!("vc-pqc binary requires the std feature");
}
