use primitive_types::{U256 as u256, U512 as u512};
use hex_literal;
use sha3::{Digest, Keccak256};
use cosmwasm_crypto::{
    secp256k1_recover_pubkey,
    CryptoError
};
use crate::error::ContractError;

const Q_BYTES:[u8; 32] = hex_literal::hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
//const Q_HALF_BYTES:[u8; 32] = hex!("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A1");

fn mod_neg<'a>(num: &'a u256, q: &'a u256) -> u256 {
    let mut res = num.clone();
    if num > q {
        res %= q;
    }
    (q - num) % q
}

fn mod_mul(a: u256, b: u256, q: u256) -> u256 {
    let res = (u512::from(a) * u512::from(b)) % u512::from(q);
    let mut b_arr: [u8; 64] = [0; 64];
    res.to_big_endian(&mut b_arr);
    u256::from(&(b_arr[32..64]))
}

pub fn schnorr_verify(
    signing_pubkey_x: [u8; 32],
    signing_pubkey_y_parity: u8,
    signature_s: [u8; 32],
    msg_hash: [u8; 32],
    nonce_address: [u8; 20]
)-> Result<bool, ContractError> {
    schnorr_verify_u256(
        u256::from_big_endian(&signing_pubkey_x),
        signing_pubkey_y_parity,
        u256::from_big_endian(&signature_s),
        u256::from_big_endian(&msg_hash),
        u256::from_big_endian(&nonce_address)
    )
}

pub fn schnorr_verify_u256(
    signing_pubkey_x: u256,
    signing_pubkey_y_parity: u8,
    signature_s: u256,
    msg_hash: u256,
    nonce_address: u256
) -> Result<bool, ContractError> {
    let Q:u256 = u256::from_big_endian(&Q_BYTES);
    let Q_HALF = (Q >> 1) + 1;

    if signing_pubkey_x >= Q_HALF {
        return Err(ContractError::LargePubkeyX {})
    }

    if signing_pubkey_x.is_zero() || nonce_address.is_zero() || msg_hash.is_zero() || signature_s.is_zero() {
        return Err(ContractError::ZeroSignatureData {})
    }

    let e = make_msg_challenge(nonce_address, msg_hash).unwrap();

    let args_z: u256 = mod_mul(mod_neg(&signing_pubkey_x, &Q), signature_s, Q);

    let args_v: u8 = signing_pubkey_y_parity;
    let args_r: u256 = signing_pubkey_x;
    let args_s: u256 = mod_mul(signing_pubkey_x, e, Q);

    let args_rs: u512 = (u512::from(args_r) << 256) + args_s;

    let mut zb: [u8; 32] = [0; 32];
    args_z.to_big_endian(&mut zb);

    let mut rs: [u8; 64] = [0; 64];
    args_rs.to_big_endian(&mut rs);

    let result = secp256k1_recover(&zb, args_v, &rs);
    let nonce_address_2 = pub_to_eth_address(&(result.unwrap()));

    let e_2 = make_msg_challenge(nonce_address_2, msg_hash).unwrap();

    Ok(e_2 == e)
}

fn pub_to_eth_address(pubkey: &[u8; 64]) -> u256 {
    let mut hasher = Keccak256::new();
    hasher.update(pubkey);
    let result = hasher.finalize();
    let mut _hash:u256 = u256::from(&result[..]);
    _hash = _hash & u256::from("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    return _hash;
}

fn make_msg_challenge (
    nonce_times_generator_address: u256, msg_hash: u256
) -> Result<u256, ContractError> {
    let mut hasher = Keccak256::new();
    let nonce_bytes:[u8; 32] = nonce_times_generator_address.into();
    let hash_bytes:[u8; 32] = msg_hash.into();
    // last 20 bytes will be used to hash
    hasher.update(&nonce_bytes[12..32]);
    hasher.update(&hash_bytes);
    let result = hasher.finalize();
    let _hash:u256 = u256::from(&result[0..32]);
    return Ok(_hash);
}

pub fn secp256k1_recover(
    hash: &[u8],
    recovery_id: u8,
    signature: &[u8],
) -> Result<[u8; 64], CryptoError> {
    let result = secp256k1_recover_pubkey(
        hash,
        signature,
        recovery_id
    )?;
    Ok(array_ref!(&result[1..65], 0, 64).clone())
}
