use schemars::JsonSchema;
use cosmwasm_std::Addr;
use serde::{Deserialize, Serialize};
use crate::types::{
    SchnorrSign,
    MuonRequestId,
    Bytes32,
    Bytes20,
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub count: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    TransferAdmin { new_admin: Addr },
    AddGroup {
        eth_address: Bytes20,
        pubkey_x: Bytes32,
        pubkey_y_parity: u8
    },
    VerifySignature {
        /// TODO: convert to [u8; 36]
        req_id: MuonRequestId,
        hash: Bytes32,
        sign: SchnorrSign
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    GetCount {},
}

// We define a custom struct for each query response
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CountResponse {
    pub count: i32,
}
