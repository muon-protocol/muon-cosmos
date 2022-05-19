use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Addr;
use cw_storage_plus::{ Item, Map};
use crate::{
    types::{Bytes32,Bytes20}
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub count: i32,
    pub owner: Addr,
}

pub const STATE: Item<State> = Item::new("state");


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AdminInfo {
    pub admin: Addr,
}

pub const ADMIN_INFO: Item<AdminInfo> = Item::new("admin");


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GroupInfo {
    pub is_valid: bool,
    pub eth_address: Bytes20,
    pub pubkey_x: Bytes32,
    pub pubkey_y_parity: u8
}

pub const GROUP_INFO: Map<Bytes20, GroupInfo> = Map::new("groups");
