use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Addr;
use cw_storage_plus::{ Item, Map};

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

pub const ADMIN_INFO: Item<State> = Item::new("admin");


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct GroupInfo {
    pub is_valid: bool,
    pub eth_address: [u8; 32],
    pub pubkey_x: [u8; 32],
    pub pubkey_y_parity: u8
}

pub const GROUP_INFO: Map<[u8; 32], GroupInfo> = Map::new("groups");
