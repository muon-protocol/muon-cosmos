use primitive_types::{U256 as u256, U512 as u512};
use hex_literal;
use sha3::{Digest, Keccak256};
use cosmwasm_crypto::{
    secp256k1_recover_pubkey,
    CryptoError
};
use {
    thiserror::Error,
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
    // TODO: replace primitive_types::U256 by native UInt256

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

//#[cfg(test)]
//mod tests {
//    struct TestSample <'a> {
//        recovery_param: u8,
//        message_hash: &'a str,
//        signature: &'a str,
//        pubkey: &'a str
//    }
//
//    #[test]
//    fn test_sign_list() {
//
//        let test_list: &[TestSample] = &[
//            TestSample {
//                recovery_param: 1u8,
//                message_hash: "5ae8317d34d1e595e3fa7247db80c0af4320cce1116de187f8f7e2e099c0d8d0",
//                signature: "45c0b7f8c09a9e1f1cea0c25785594427b6bf8f9f878a8af0b1abbb48e16d0920d8becd0c220f67c51217eecfd7184ef0732481c843857e6bc7fc095c4f6b78801",
//                pubkey: "044a071e8a6e10aada2b8cf39fa3b5fb3400b04e99ea8ae64ceea1a977dbeaf5d5f8c8fbd10b71ab14cd561f7df8eb6da50f8a8d81ba564342244d26d1d4211595"
//            },
//            TestSample {
//                recovery_param: 1u8,
//                message_hash: "586052916fb6f746e1d417766cceffbe1baf95579bab67ad49addaaa6e798862",
//                signature: "4e0ea79d4a476276e4b067facdec7460d2c98c8a65326a6e5c998fd7c65061140e45aea5034af973410e65cf97651b3f2b976e3fc79c6a93065ed7cb69a2ab5a01",
//                pubkey: "04dbf1f4092deb3cfd4246b2011f7b24840bc5dbedae02f28471ce5b3bfbf06e71b320e42149e6d12ed8c717c5990359bb4f9bded9de674375b2f0ca0268748c8e"
//            },
//            TestSample {
//                recovery_param: 0u8,
//                message_hash: "c36d0ecf4bfd178835c97aae7585f6a87de7dfa23cc927944f99a8d60feff68b",
//                signature: "f25b86e1d8a11d72475b3ed273b0781c7d7f6f9e1dae0dd5d3ee9b84f3fab89163d9c4e1391de077244583e9a6e3d8e8e1f236a3bf5963735353b93b1a3ba93500",
//                pubkey: "04414549fd05bfb7803ae507ff86b99becd36f8d66037a7f5ba612792841d42eb959a0799bcdaa3b5e106f50add1ec4edf6e03fca8642a6a1c65ae078287eec9a5",
//            },
//            TestSample {
//                recovery_param: 1u8,
//                message_hash: "a761293b02c5d8327f909d61a38173556c1f1f770c488810a9b360cf7786c148",
//                signature: "f2cab57d108aaf7c9c9dd061404447d59f968d1468b25dd827d624b64601c32a77558dbf7bf90885b9128c371959085e9dd1b7d8a5c45b7265e8e7d9f125c00801",
//                pubkey: "041074702a456f9247ea07967b07d3b8def64aa932d80027dc90df74578a522504152f51ab5a5937d7bb82f38877ece243db6c0e894bfa46fe19c5b7abff4247b4",
//            },
//            TestSample {
//                recovery_param: 0u8,
//                message_hash: "08ec76ab0f1bc9dc27b3b3bd4f949c60ecc8bbf27678b28f2ee8de055ee8bf59",
//                signature: "d702bec0f058f5e18f5fcdb204f79250562f11121f5513ae1006c9b93ddafb1163de551c508405a280a21fb007b660542b58fcd3256b7cea45e3f2ebe9a29ecd00",
//                pubkey: "0482bdcaa5613930c51b993443a5dfaad41cf9b3d77e7a224283ffa96d0d546bdc8b2f6841a9d41e9fdf33de9f79f45323ad030e52c914ad3df36e95a4d4eef527",
//            },
//            TestSample {
//                recovery_param: 1u8,
//                message_hash: "ffbe3fd342a1a991848d02258cf5e3df301974b7a8f0fe10a88222a9503f67e0",
//                signature: "ae17ab6a3bd2ccd0901cc3904103e825895540bf416a5f717b74b529512e4c184bc049a8a2287cfccea77fb3769755ba92c35154c635448cf633244edf4f6fe101",
//                pubkey: "047dfd5be333e217f99b7b936452499f34a937268f1131d3ea36aa0fae7f6ccb177b68596c7db85ffe71a1d918f2c95a573a9735d3088b25cb53f57b6b8f1c24a3",
//            },
//            TestSample {
//                recovery_param: 0u8,
//                message_hash: "434fea583df79f781e41f18735a24409cf404f28e930290cc97c67ef158e5789",
//                signature: "03b51d02eac41f2969fc36c816c9772da21a139376b09d1c8809bb8f543be62f0629c1396ae304d2c2e7b63890d91e56dfc3459f4d664cb914c7ff2a12a2192500",
//                pubkey: "04b3c3074d378b98b1fa1456dc83611512bc7f351c90e4cf083dce80fd8c4e95693d88c8538194701bbc6e217046080755bf76e45a7d77a689f0368d6bd8b4d41c",
//            },
//            TestSample {
//                recovery_param: 1u8,
//                message_hash: "c352f58e118fc0d7810b8020bdb306b7dc115b41bbb0b642c7ea73a60cc2a4eb",
//                signature: "400f52f4c4925b4b8886706331535230fafb6455c3a3eef6fbf19a8259381230727cc4b3341d7d95d0dc404d910dc009b3b5f21baadc0c4ee199a46e558d7f5601",
//                pubkey: "043edd1cfab2ad7d0ba623a5780c3fa31b71031aa2cdbbde3b90199c06285a3848966377a8c08645abcc07a9c911460a6fef73801e1330970c8727fda9e7488172",
//            },
//            TestSample {
//                recovery_param: 0u8,
//                message_hash: "6ff9153ede285fc0e486f1dd4dd9e32a0fb23e9653c55841b67c2e5a090aac63",
//                signature: "b2927afc8856b7e14d02e01e7aa3c76951a4621bfde5d794adda165b51dbe19806eee6e0b087143ed06933cba699fbe4097ba7d7b038b173cbbd183718a86d4300",
//                pubkey: "045ea6df29756aad4c249d7432c0573308aa4be0666bf321e791795cdf41627d74f6aa44de02570075eec50bb6ac1e7d8a38fcf7aadafdc68badcc78b846ca3003",
//            },
//            TestSample {
//                recovery_param: 0u8,
//                message_hash: "8e19143e34fee546fab3d56e816f2e21586e27912a2ad7d80af75942e0ff585a",
//                signature: "fe9717965673fbe585780e18d892a3cfa77b59ac2f44f5337a3e58ce6ecd440900155459b19d2e9a2e676d7d8d48a9303391ffb9befdd3a57324306d69e0e0ab00",
//                pubkey: "04968de976bab658da49e4f8f629aa515dbe117de8e0d602477fcf0427e1a6944b4dbbff053f864ad7d5771e6a38f6f0df38b56a4e8d9caf9724a09b8cc8c4f843",
//            }
//        ];
//
//        for sample in test_list.iter() {
//        }
//    }
//}
