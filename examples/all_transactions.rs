//! examples/all_transactions.rs
//!
//! Comprehensive example showing multiple Bitcoin transaction types

use bitcoin_tx_rust::*;

fn main() {
    println!("=== Bitcoin Transaction Examples ===\n");

    // 1. P2WPKH Single Input
    println!("1. P2WPKH Single Input Transaction");
    println!("-----------------------------------");
    example_p2wpkh_single_input();

    // 2. P2WPKH Multiple Inputs
    println!("\n2. P2WPKH Multiple Inputs Transaction");
    println!("--------------------------------------");
    example_p2wpkh_multiple_inputs();

    // 3. P2WSH 2-of-2 Multisig
    println!("\n3. P2WSH 2-of-2 Multisig Transaction");
    println!("------------------------------------");
    example_p2wsh_2of2_multisig();

    // 4. P2WSH 3-of-5 Multisig
    println!("\n4. P2WSH 3-of-5 Multisig Transaction");
    println!("------------------------------------");
    example_p2wsh_3of5_multisig();

    // 5. Legacy P2SH 2-of-3 Multisig
    println!("\n5. Legacy P2SH 2-of-3 Multisig Transaction");
    println!("------------------------------------------");
    example_legacy_p2sh();
}

fn example_legacy_p2sh() {
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

    let funding_txid = [0x70u8; 32];
    tx.add_input(funding_txid, 0, 200_100_000); // txid, vout, amount

    let output_spk = hex::decode("76a9143bc28d6d92d9073fb5e3adf481795eaf446bceed88ac").unwrap();
    tx.add_output(150_000_000, output_spk);

    // Sign with 2 keys (one Vec per input)
    let signed_tx = tx.sign(&[vec![privkey1, privkey2]]).unwrap();

    println!("Signed P2SH transaction: {}", hex::encode(&signed_tx));
    println!("Transaction size: {} bytes", signed_tx.len());
}

fn example_p2wpkh_single_input() {
    let sender_privkey = [0x11u8; 32];
    let sender_pubkey = privkey_to_pubkey(&sender_privkey).unwrap();

    let sender_address = pk_to_p2wpkh(&sender_pubkey, "regtest").unwrap();
    println!("Sender P2WPKH address: {}", sender_address);

    let receiver_address = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";
    let receiver_spk = bech32_to_spk("bcrt", receiver_address).unwrap();

    let change_privkey = [0x22u8; 32];
    let change_pubkey = privkey_to_pubkey(&change_privkey).unwrap();
    let change_address = pk_to_p2wpkh(&change_pubkey, "regtest").unwrap();
    let change_spk = bech32_to_spk("bcrt", &change_address).unwrap();

    let mut tx = P2WPKHTransaction::new();

    let txid = [0xd4u8; 32];
    tx.add_input(txid, 0, receiver_spk.clone(), 200_100_000); // dummy input spk & amount

    tx.add_output(150_000_000, receiver_spk);
    tx.add_output(50_000_000, change_spk);

    let signed_tx = tx.sign(&[sender_privkey]).unwrap();

    println!("Signed transaction: {}", hex::encode(&signed_tx));
    println!("Transaction size: {} bytes", signed_tx.len());
}

fn example_p2wpkh_multiple_inputs() {
    let privkey_andreas = [0x11u8; 32];
    let privkey_lisa = [0x22u8; 32];

    let addr_andreas =
        pk_to_p2wpkh(&privkey_to_pubkey(&privkey_andreas).unwrap(), "regtest").unwrap();
    let addr_lisa = pk_to_p2wpkh(&privkey_to_pubkey(&privkey_lisa).unwrap(), "regtest").unwrap();

    println!("Andreas's address: {}", addr_andreas);
    println!("Lisa's address: {}", addr_lisa);

    let mut tx = MultiInputP2WPKHTransaction::new();

    let dummy_spk = vec![
        0x00u8, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    tx.add_input([0x44u8; 32], 0, dummy_spk.clone(), 30_000_000);
    tx.add_input([0xd2u8; 32], 0, dummy_spk.clone(), 40_100_000);

    let charity1 = bech32_to_spk("bcrt", "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw").unwrap();
    let charity2 = bech32_to_spk("bcrt", "bcrt1q6mlqttg852e63uahyglwla55xusryqp08vx9w2").unwrap();
    let charity3 = bech32_to_spk("bcrt", "bcrt1qe9y40n9uwzh34mzj02w3xx9zkhgke6wxcql4lk").unwrap();

    tx.add_output(20_000_000, charity1);
    tx.add_output(20_000_000, charity2);
    tx.add_output(20_000_000, charity3);

    let lisa_change =
        bech32_to_spk("bcrt", "bcrt1qqde3c4pmvrr9d3pav3v6hlpp9l3sm6rxnj8dcm").unwrap();
    tx.add_output(10_000_000, lisa_change);

    let signed_tx = tx.sign(&[privkey_andreas, privkey_lisa]).unwrap();

    println!(
        "\nSigned multi-input transaction: {}",
        hex::encode(&signed_tx)
    );
    println!("Transaction size: {} bytes", signed_tx.len());
}

fn example_p2wsh_2of2_multisig() {
    let privkey1 = [0x11u8; 32];
    let privkey2 = [0x22u8; 32];

    let pubkey1 = privkey_to_pubkey(&privkey1).unwrap();
    let pubkey2 = privkey_to_pubkey(&privkey2).unwrap();

    let redeem_script = P2WSHMultisigTransaction::create_2of2_redeem_script(&pubkey1, &pubkey2);

    let address = script_to_p2wsh(&redeem_script, "regtest").unwrap();
    println!("P2WSH address: {}", address);

    let mut tx = P2WSHMultisigTransaction::new(redeem_script);

    let funding_txid = [0x13u8; 32];
    tx.add_input(funding_txid, 0, 200_100_000);

    let receiver_address = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";
    let receiver_spk = bech32_to_spk("bcrt", receiver_address).unwrap();
    tx.add_output(150_000_000, receiver_spk);

    let change_privkey = [0x44u8; 32];
    let change_pubkey = privkey_to_pubkey(&change_privkey).unwrap();
    let change_address = pk_to_p2wpkh(&change_pubkey, "regtest").unwrap();
    let change_spk = bech32_to_spk("bcrt", &change_address).unwrap();
    tx.add_output(50_000_000, change_spk);

    let signed_tx = tx.sign(&[vec![privkey1, privkey2]]).unwrap();

    println!("Signed P2WSH transaction: {}", hex::encode(&signed_tx));
    println!("Transaction size: {} bytes", signed_tx.len());
}

fn example_p2wsh_3of5_multisig() {
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

    let redeem_script =
        P2WSHMultisigTransaction::create_multisig_redeem_script(3, &pubkeys).unwrap();

    let address = script_to_p2wsh(&redeem_script, "regtest").unwrap();
    println!("3-of-5 P2WSH address: {}", address);

    let mut tx = P2WSHMultisigTransaction::new(redeem_script);

    let funding_txid = [0xAAu8; 32];
    tx.add_input(funding_txid, 0, 100_000_000);

    let output_address = "bcrt1ql3e9pgs3mmwuwrh95fecme0s0qtn2880hlwwpw";
    let output_spk = bech32_to_spk("bcrt", output_address).unwrap();
    tx.add_output(99_900_000, output_spk);

    let signing_keys = vec![vec![privkeys[0], privkeys[1], privkeys[2]]];

    let signed_tx = tx.sign(&signing_keys).unwrap();

    println!(
        "Signed 3-of-5 multisig transaction: {}",
        hex::encode(&signed_tx)
    );
    println!("Transaction size: {} bytes", signed_tx.len());
}
