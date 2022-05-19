//use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::construct_fixed_bytes;
use cosmwasm_std::{StdResult};
use cw_storage_plus::{
    PrimaryKey,
    KeyDeserialize,
    Key,
};

construct_fixed_bytes! { pub struct MuonRequestId(36); }
construct_fixed_bytes! { pub struct Bytes32(32); }
construct_fixed_bytes! { pub struct Bytes20(20); }

impl<'a> PrimaryKey<'a> for &'a Bytes20 {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        // this is simple, we don't add more prefixes
        vec![Key::Ref(&self.0[..])]
    }
}

impl PrimaryKey<'_> for Bytes20 {
    type Prefix = ();
    type SubPrefix = ();
    type Suffix = Self;
    type SuperSuffix = Self;

    fn key(&self) -> Vec<Key> {
        // this is simple, we don't add more prefixes
        vec![Key::Ref(&self.0[..])]
    }
}

impl KeyDeserialize for Bytes20 {
    type Output = Vec<u8>;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(value)
    }
}

impl<'a> KeyDeserialize for &'a Bytes20 {
    type Output = Vec<u8>;

    #[inline(always)]
    fn from_vec(value: Vec<u8>) -> StdResult<Self::Output> {
        Ok(value)
    }
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SchnorrSign {
    // s value of signature
    pub signature: Bytes32,
    // ethereum address of signer
    pub address: Bytes32,
    // ethereum address of nonce
    pub nonce: Bytes32
}
