use bitcoin_tx_rust::*;

fn main() {
    println!("=== Bitcoin Transaction Examples ===\n");

    // Example 1: P2WPKH Single Input Transaction
    println!("1. P2WPKH Single Input Transaction");
    println!("-----------------------------------");
    example_p2wpkh_single_input();

    // Example 2: P2WPKH Multiple Inputs
    println!("\n2. P2WPKH Multiple Inputs Transaction");
    println!("--------------------------------------");
    example_p2wpkh_multiple_inputs();

    // Example 3: P2WSH 2-of-2 Multisig
    println!("\n3. P2WSH 2-of-2 Multisig Transaction");
    println!("------------------------------------");
    example_p2wsh_2of2_multisig();

    // Example 4: P2WSH 3-of-5 Multisig
    println!("\n4. P2WSH 3-of-5 Multisig Transaction");
    println!("------------------------------------");
    example_p2wsh_3of5_multisig();

    // Example 5: Legacy P2SH 2-of-3 Multisig
    println!("\n5. Legacy P2SH 2-of-3 Multisig Transaction");
    println!("------------------------------------------");
    example_legacy_p2sh();
}

fn example_legacy_p2sh() {
    println!("\n5. Legacy P2SH 2-of-3 Multisig Transaction");
    println!("------------------------------------------");

    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];
    let privkey3 = [0x33u8; 32];

    let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
    let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();
    let pubkey3 = privkey_to_pubkey(&privkey3).unwrap();

    let redeem_script =
        legacy::P2SHMultisigTransaction::create_2of3_redeem_script(&pubkey1, &pubkey2, &pubkey3);

    let address = legacy::P2SHMultisigTransaction::script_to_p2sh(&redeem_script, "regtest");
    println!("P2SH address: {}", address);

    let mut tx = legacy::P2SHMultisigTransaction::new(redeem_script);
    tx.add_input(TxInput::new([0x70u8; 32], 0));

    let output_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
    tx.add_output(TxOutput::new(150_000_000, output_spk));

    let signed_tx = tx.sign(&[privkey1, privkey2], 0).unwrap();
    println!("Signed P2SH transaction: {}", hex::encode(&signed_tx));
    println!("Transaction size: {} bytes", signed_tx.len());
}

fn example_p2wpkh_single_input() {
    // Generate sender's keys
    let sender_privkey = [0x11u8; 32];
    let sender_pubkey = privkey_to_pubkey(&sender_privkey).unwrap();

    println!("Sender private key: {}", hex::encode(&sender_privkey));
    println!("Sender public key: {}", hex::encode(&sender_pubkey));

    // Create sender's address
    let sender_address = pk_to_p2wpkh(&sender_pubkey, "regtest").unwrap();
    println!("Sender P2WPKH address: {}", sender_address);

    // Receiver address
    let receiver_address = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";
    let receiver_spk = bech32_to_spk("bcrt", receiver_address).unwrap();
    println!("Receiver address: {}", receiver_address);

    // Create change output
    let change_privkey = [0x22u8; 32];
    let change_pubkey = privkey_to_pubkey(&change_privkey).unwrap();
    let change_address = pk_to_p2wpkh(&change_pubkey, "regtest").unwrap();
    println!("Change address: {}", change_address);

    // Build transaction
    let mut tx = P2WPKHTransaction::new();

    // Simulated UTXO to spend
    let txid = [
        0xd4, 0xce, 0x50, 0x31, 0x1e, 0xfa, 0x12, 0xa9, 0x7b, 0x6c, 0x91, 0x0a, 0xfb, 0xa1, 0x80,
        0x68, 0x66, 0x87, 0xed, 0xae, 0xc7, 0xde, 0x92, 0xff, 0xcf, 0xba, 0x18, 0x77, 0x76, 0x73,
        0x99, 0x1c,
    ];

    tx.add_input(TxInput::new(txid, 0));

    // Add outputs: 1.5 BTC to receiver, 0.5 BTC change
    tx.add_output(TxOutput::new(150_000_000, receiver_spk));

    let change_pk_hash = hash160(&change_pubkey);
    let mut change_spk = vec![0x00, 0x14];
    change_spk.extend_from_slice(&change_pk_hash);
    tx.add_output(TxOutput::new(50_000_000, change_spk));

    // Build unsigned transaction
    let unsigned_tx = tx.build_unsigned();
    println!("\nUnsigned transaction: {}", hex::encode(&unsigned_tx));

    // Sign transaction (input value: 2.001 BTC)
    let input_value = 200_100_000;
    let signed_tx = tx
        .sign(&sender_privkey, &sender_pubkey, input_value)
        .unwrap();
    println!("Signed transaction: {}", hex::encode(&signed_tx));
    println!("Transaction size: {} bytes", signed_tx.len());
}

fn example_p2wpkh_multiple_inputs() {
    // Andreas's keys
    let privkey_andreas = [0x11u8; 32];
    let pubkey_andreas = privkey_to_pubkey(&privkey_andreas).unwrap();
    let addr_andreas = pk_to_p2wpkh(&pubkey_andreas, "regtest").unwrap();

    // Lisa's keys
    let privkey_lisa = [0x22u8; 32];
    let pubkey_lisa = privkey_to_pubkey(&privkey_lisa).unwrap();
    let addr_lisa = pk_to_p2wpkh(&pubkey_lisa, "regtest").unwrap();

    println!("Andreas's address: {}", addr_andreas);
    println!("Lisa's address: {}", addr_lisa);

    // Create transaction
    let mut tx = MultiInputP2WPKHTransaction::new();

    // Add both inputs
    let txid_andreas = [0x44u8; 32];
    let txid_lisa = [0xd2u8; 32];

    tx.add_input(TxInput::new(txid_andreas, 0));
    tx.add_input(TxInput::new(txid_lisa, 0));

    // Three charity outputs (0.2 BTC each)
    let charity1 = bech32_to_spk("bcrt", "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw").unwrap();
    let charity2 = bech32_to_spk("bcrt", "bcrt1q6mlqttg852e63uahyglwla55xusryqp08vx9w2").unwrap();
    let charity3 = bech32_to_spk("bcrt", "bcrt1qe9y40n9uwzh34mzj02w3xx9zkhgke6wxcql4lk").unwrap();

    tx.add_output(TxOutput::new(20_000_000, charity1));
    tx.add_output(TxOutput::new(20_000_000, charity2));
    tx.add_output(TxOutput::new(20_000_000, charity3));

    // Lisa's change (0.1 BTC)
    let lisa_change =
        bech32_to_spk("bcrt", "bcrt1qqde3c4pmvrr9d3pav3v6hlpp9l3sm6rxnj8dcm").unwrap();
    tx.add_output(TxOutput::new(10_000_000, lisa_change));

    println!("\nTotal outputs: 0.7 BTC");
    println!("Andreas contributes: 0.3 BTC");
    println!("Lisa contributes: 0.3 BTC (+ 0.1 BTC change)");
    println!("Fee: 0.001 BTC");

    // Sign with both keys
    let input_data = vec![
        (privkey_andreas.to_vec(), pubkey_andreas, 30_000_000), // 0.3 BTC
        (privkey_lisa.to_vec(), pubkey_lisa, 40_100_000),       // 0.401 BTC
    ];

    let signed_tx = tx.sign(&input_data).unwrap();
    println!(
        "\nSigned multi-input transaction: {}",
        hex::encode(&signed_tx)
    );
    println!("Transaction size: {} bytes", signed_tx.len());
}

fn example_p2wsh_2of2_multisig() {
    // Create two keypairs for 2-of-2 multisig
    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];

    let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
    let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

    println!("Pubkey 1: {}", hex::encode(&pubkey1));
    println!("Pubkey 2: {}", hex::encode(&pubkey2));

    // Create 2-of-2 redeem script
    let redeem_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);
    println!("\nRedeem script: {}", hex::encode(&redeem_script));

    // Create P2WSH address
    let p2wsh_address = script_to_p2wsh(&redeem_script, "regtest").unwrap();
    println!("P2WSH address: {}", p2wsh_address);

    // Create transaction to spend from the multisig
    let mut tx = P2WSHMultisigTransaction::new(redeem_script);

    let funding_txid = [0x13u8; 32];
    tx.add_input(TxInput::new(funding_txid, 0));

    // Receiver (P2WPKH for variety)
    let receiver_address = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";
    let receiver_spk = bech32_to_spk("bcrt", receiver_address).unwrap();
    tx.add_output(TxOutput::new(150_000_000, receiver_spk));

    // Change output
    let change_privkey = [0x44u8; 32];
    let change_pubkey = privkey_to_pubkey(&change_privkey).unwrap();
    let change_address = pk_to_p2wpkh(&change_pubkey, "regtest").unwrap();
    let change_spk = bech32_to_spk("bcrt", &change_address).unwrap();
    tx.add_output(TxOutput::new(50_000_000, change_spk));

    println!("\nSigning with both private keys...");

    // Sign with both keys (input value: 2.001 BTC)
    let signed_tx = tx.sign(&[privkey1, privkey2], 200_100_000).unwrap();
    println!("Signed P2WSH transaction: {}", hex::encode(&signed_tx));
    println!("Transaction size: {} bytes", signed_tx.len());
}

fn example_p2wsh_3of5_multisig() {
    println!("Creating a 3-of-5 multisig setup (requires 3 out of 5 signatures)");

    // Generate 5 keypairs
    let privkeys: Vec<[u8; 32]> = (1..=5)
        .map(|i| {
            let mut key = [0u8; 32];
            key[0] = (i * 0x11) as u8;
            key
        })
        .collect();

    let pubkeys: Vec<Vec<u8>> = privkeys
        .iter()
        .map(|pk| privkey_to_pubkey(pk).unwrap())
        .collect();

    println!("\nGenerated 5 public keys:");
    for (i, pk) in pubkeys.iter().enumerate() {
        println!("  Key {}: {}", i + 1, hex::encode(pk));
    }

    // Create 3-of-5 multisig redeem script
    let redeem_script =
        P2WSHMultisigTransaction::create_multisig_redeem_script(3, &pubkeys).unwrap();
    println!("\n3-of-5 Redeem script: {}", hex::encode(&redeem_script));

    // Create P2WSH address
    let address = script_to_p2wsh(&redeem_script, "regtest").unwrap();
    println!("3-of-5 P2WSH address: {}", address);

    // Create transaction
    let mut tx = P2WSHMultisigTransaction::new(redeem_script);

    let funding_txid = [0xAAu8; 32];
    tx.add_input(TxInput::new(funding_txid, 0));

    // Single output
    let output_address = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";
    let output_spk = bech32_to_spk("bcrt", output_address).unwrap();
    tx.add_output(TxOutput::new(99_900_000, output_spk)); // 0.999 BTC (0.001 BTC fee)

    println!("\nSigning with keys 1, 2, and 3 (any 3 of the 5 would work)...");

    // Sign with first 3 keys
    let signing_keys = [privkeys[0], privkeys[1], privkeys[2]];
    let signed_tx = tx.sign(&signing_keys, 100_000_000).unwrap();

    println!(
        "Signed 3-of-5 multisig transaction: {}",
        hex::encode(&signed_tx)
    );
    println!("Transaction size: {} bytes", signed_tx.len());
    println!("\n✓ Successfully created and signed a 3-of-5 multisig transaction!");
}
