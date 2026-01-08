use bitcoin::PublicKey;
use bitcoin::XOnlyPublicKey;
use bitcoin::address::{Address, NetworkUnchecked, Payload};
use bitcoin::key::Secp256k1;
use bitcoin::network::Network as BitcoinNetwork;
use bitcoin::script::ScriptBuf;

/// Convert a compressed public key (33 bytes) to a P2WPKH (native SegWit) address
pub fn pk_to_p2wpkh(pubkey: &[u8], network: &str) -> Result<String, Box<dyn std::error::Error>> {
    let pubkey = PublicKey::from_slice(pubkey)?;
    let bitcoin_network = match network {
        "mainnet" => BitcoinNetwork::Bitcoin,
        "testnet" => BitcoinNetwork::Testnet,
        "regtest" => BitcoinNetwork::Regtest,
        _ => return Err("Invalid network".into()),
    };

    let address = Address::p2wpkh(&pubkey, bitcoin_network)?;
    Ok(address.to_string())
}

/// Decode a Bech32/Bech32m address → (witness version, program bytes)
pub fn decode_bech32(
    expected_hrp: &str,
    address: &str,
) -> Result<(u8, Vec<u8>), Box<dyn std::error::Error>> {
    let addr: Address<NetworkUnchecked> = address.parse()?;
    let addr = addr.require_network(match expected_hrp {
        "bc" => BitcoinNetwork::Bitcoin,
        "tb" => BitcoinNetwork::Testnet,
        "bcrt" => BitcoinNetwork::Regtest,
        _ => return Err("Unsupported HRP".into()),
    })?;

    let payload = addr.payload(); // owned for matching

    match payload {
        Payload::WitnessProgram(wp) => {
            Ok((wp.version().to_num(), wp.program().as_bytes().to_vec()))
        }
        _ => Err("Not a SegWit address".into()),
    }
}

/// Convert a Bech32/Bech32m address directly to its scriptPubKey
pub fn bech32_to_spk(
    expected_hrp: &str,
    address: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let addr: Address<NetworkUnchecked> = address.parse()?;
    let addr = addr.require_network(match expected_hrp {
        "bc" => BitcoinNetwork::Bitcoin,
        "tb" => BitcoinNetwork::Testnet,
        "bcrt" => BitcoinNetwork::Regtest,
        _ => return Err("Unsupported HRP".into()),
    })?;

    Ok(addr.script_pubkey().to_bytes())
}

/// Convert a redeem script to a P2WSH (native SegWit witness script) address
pub fn script_to_p2wsh(script: &[u8], network: &str) -> Result<String, Box<dyn std::error::Error>> {
    let script_buf = ScriptBuf::from_bytes(script.to_vec());

    let bitcoin_network = match network {
        "mainnet" => BitcoinNetwork::Bitcoin,
        "testnet" => BitcoinNetwork::Testnet,
        "regtest" => BitcoinNetwork::Regtest,
        _ => return Err("Invalid network".into()),
    };

    let address = Address::p2wsh(&script_buf, bitcoin_network);
    Ok(address.to_string())
}

/// Convert a 32-byte x-only tweaked public key to a P2TR (Taproot) address
///
/// `pubkey` must be the **final tweaked** x-only public key (32 bytes)
/// This is what you get from `taproot_tweak_pubkey(...).1`.
pub fn taproot_address(pubkey: &[u8], network: &str) -> Result<String, Box<dyn std::error::Error>> {
    if pubkey.len() != 32 {
        return Err("Taproot public key must be 32 bytes (x-only)".into());
    }

    let secp = Secp256k1::new();
    let xonly = XOnlyPublicKey::from_slice(pubkey)?;

    let bitcoin_network = match network {
        "mainnet" => BitcoinNetwork::Bitcoin,
        "testnet" => BitcoinNetwork::Testnet,
        "regtest" => BitcoinNetwork::Regtest,
        _ => return Err("Invalid network".into()),
    };

    let address = Address::p2tr(&secp, xonly, None, bitcoin_network);
    Ok(address.to_string())
}
