#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Addr, Order
};
use cw2::set_contract_version;

use crate::{
    error::ContractError,
    msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{
        AdminInfo, ADMIN_INFO,
        GroupInfo, GROUP_INFO,
    },
    types::{SchnorrSign, MuonRequestId, Bytes20, Bytes32},
    utils::schnorr_verify
};
use crate::msg::{AdminResponse, GroupInfoResponse, GroupListResponse};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:muon-cosmos";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    let admin_info = AdminInfo {
        admin: info.sender.clone(),
    };

    ADMIN_INFO.save(deps.storage, &admin_info)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("admin", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::TransferAdmin { new_admin } => try_transfer_admin(deps, info, new_admin),
        ExecuteMsg::AddGroup {
            eth_address,
            pubkey_x,
            pubkey_y_parity
        } => try_add_group(deps, info, eth_address, pubkey_x, pubkey_y_parity),
        ExecuteMsg::VerifySignature {
            req_id,
            hash,
            sign
        } => try_verify_sign(deps, req_id, hash, sign),
    }
}

pub fn try_transfer_admin(deps: DepsMut, info: MessageInfo, new_admin: Addr) -> Result<Response, ContractError> {
    let admin_info = ADMIN_INFO.load(deps.storage)?;
    if admin_info.admin != info.sender {
        return Err(ContractError::AdminRestricted {});
    }

    ADMIN_INFO.update(deps.storage, |mut admin_info| -> Result<_, ContractError> {
        admin_info.admin = new_admin.clone();
        Ok(admin_info)
    })?;

    Ok(Response::new()
        .add_attribute("method", "transfer_admin")
        .add_attribute("to", new_admin)
    )
}

pub fn try_add_group(
    deps: DepsMut,
    info: MessageInfo,
    eth_address: Bytes20,
    pubkey_x: Bytes32,
    pubkey_y_parity: u8
) -> Result<Response, ContractError> {
    let admin_info = ADMIN_INFO.load(deps.storage)?;
    if admin_info.admin != info.sender {
        return Err(ContractError::AdminRestricted {});
    }

    let group_info = GroupInfo {
        is_valid: true,
        eth_address: eth_address.clone(),
        pubkey_x: pubkey_x.clone(),
        pubkey_y_parity
    };
    GROUP_INFO.save(deps.storage, eth_address.clone(), &group_info)?;

    Ok(
        Response::new()
            .add_attribute("method", "add_group")
            .add_attribute("eth_address", hex::encode(eth_address))
            .add_attribute("pubkey_x", hex::encode(pubkey_x))
            .add_attribute("pubkey_y_parity", hex::encode([pubkey_y_parity]))
    )
}

pub fn try_verify_sign(
    deps: DepsMut,
    req_id: MuonRequestId,
    hash: Bytes32,
    sign: SchnorrSign
) -> Result<Response, ContractError> {

    let group_info = GROUP_INFO.load(deps.storage, sign.address)?;

    let is_verified = schnorr_verify(
        group_info.pubkey_x.0,
        group_info.pubkey_y_parity,
        sign.signature.0,
        hash.0,
        sign.nonce.0
    )?;

    if !is_verified {
        return Err(ContractError::NotVerified {});
    }

    Ok(
        Response::new()
            .add_attribute("verified", if is_verified { "true" } else { "false" })
            .add_attribute("req_id", hex::encode(req_id.0))
            .add_attribute("group", hex::encode(group_info.eth_address.0))
    )
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetAdmin {} => to_binary(&query_admin(deps)?),
        QueryMsg::GetGroupList {} => to_binary(&query_groups_list(deps)?),
        QueryMsg::GetGroupInfo { group } => to_binary(&query_group_info(deps, group)?),
    }
}

fn query_admin(deps: Deps) -> StdResult<AdminResponse> {
    let admin_info = ADMIN_INFO.load(deps.storage)?;
    Ok(AdminResponse { admin: admin_info.admin })
}

fn query_groups_list(deps: Deps) -> StdResult<GroupListResponse> {
    let groups: Vec<GroupInfo> = GROUP_INFO
        .range(deps.storage, None, None, Order::Ascending)
        .map(|_res| _res.unwrap().1)
        .collect();
    Ok(GroupListResponse {groups})
}

fn query_group_info(deps: Deps, eth_address: Bytes20) -> StdResult<GroupInfoResponse> {
    let group_info = GROUP_INFO.load(deps.storage, eth_address)?;
    Ok(GroupInfoResponse {group: group_info})
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies_with_balance, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));

        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, InstantiateMsg {}).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetAdmin {}).unwrap();
        let value: AdminResponse = from_binary(&res).unwrap();
        assert_eq!("creator", value.admin);
    }

    #[test]
    fn transfer_admin() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));

        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();

        let new_admin = Addr::unchecked("new-admin");
        let msg = ExecuteMsg::TransferAdmin { new_admin: new_admin.clone() };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // should increase counter by 1
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetAdmin {}).unwrap();
        let value: AdminResponse = from_binary(&res).unwrap();
        assert_eq!(new_admin, value.admin);
    }

    #[test]
    fn add_group() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));

        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), InstantiateMsg {}).unwrap();


        let hacker_info = mock_info("hacker", &coins(2, "token"));
        let add_1 = ExecuteMsg::AddGroup {
            eth_address: Bytes20::from(hex::decode("834AED40952Dd195ca2A5eB110E101E5461B5955").unwrap()),
            pubkey_x: Bytes32::from(hex::decode("2b6ac5ee66c087425ceab6a4e78bcbbdda29829e1f0ba9ff0a35add28001244a").unwrap()),
            pubkey_y_parity: 1u8
        };
        let _res = execute(deps.as_mut(), mock_env(), hacker_info, add_1.clone());
        assert!(_res.is_err());
        let msg: String = format!("{}", _res.unwrap_err());
        assert!(msg.contains("Admin Restricted"));

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), add_1.clone()).unwrap();

        let add_2 = ExecuteMsg::AddGroup {
            eth_address: Bytes20::from(hex::decode("F096EC73cB49B024f1D93eFe893E38337E7a099a").unwrap()),
            pubkey_x: Bytes32::from(hex::decode("0eae3877457595b4884e6fffa853ad34ca19cb142e06e90796c3cdf983893b8d").unwrap()),
            pubkey_y_parity: 1u8
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), add_2.clone()).unwrap();

        // should increase counter by 1
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetGroupList {}).unwrap();
        let value: GroupListResponse = from_binary(&res).unwrap();
        assert_eq!(2, value.groups.len());

        if let ExecuteMsg::AddGroup {eth_address, pubkey_x, pubkey_y_parity} = add_1 {
            assert_eq!(eth_address, value.groups[0].eth_address);
            assert_eq!(pubkey_x, value.groups[0].pubkey_x);
            assert_eq!(pubkey_y_parity, value.groups[0].pubkey_y_parity);
        }
        if let ExecuteMsg::AddGroup {eth_address, pubkey_x, pubkey_y_parity} = add_2 {
            assert_eq!(eth_address, value.groups[1].eth_address);
            assert_eq!(pubkey_x, value.groups[1].pubkey_x);
            assert_eq!(pubkey_y_parity, value.groups[1].pubkey_y_parity);
        }
    }

    #[test]
    fn true_verification() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));
        let info = mock_info("creator", &coins(2, "token"));

        // Instantiate
        let _res = instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {}
        ).unwrap();

        let eth_address: Bytes20 = Bytes20::from(hex::decode("834AED40952Dd195ca2A5eB110E101E5461B5955").unwrap());
        let pubkey_x: Bytes32 = Bytes32::from(hex::decode("2b6ac5ee66c087425ceab6a4e78bcbbdda29829e1f0ba9ff0a35add28001244a").unwrap());

        // Add Group
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::AddGroup { eth_address, pubkey_x, pubkey_y_parity: 1u8 }
        ).unwrap();

        let req_id: MuonRequestId = MuonRequestId::from(hex::decode("0170122020a3a823f77a2ebef3fa130a6ff9a776225abd47a8997916af73cfaa7126299b").unwrap());
        let hash: Bytes32 = Bytes32::from(hex::decode("2d9fff2a7ab727ab3a0b82110e010fa1f0255381ea4e3bdfd2157c31836189ae").unwrap());
        let signature: Bytes32 = Bytes32::from(hex::decode("058cc5fdca29e04243490de0290cf517bf2d1d1556b61687040443179c964358").unwrap());
        let address: Bytes20 = Bytes20::from(hex::decode("834AED40952Dd195ca2A5eB110E101E5461B5955").unwrap());
        let nonce: Bytes20 = Bytes20::from(hex::decode("111134Af4fa82F852CF7c35fC8082B2e13E68404").unwrap());

        // Add Group
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::VerifySignature { req_id, hash, sign: SchnorrSign { signature, address, nonce } }
        ).unwrap();

        println!("============================================");
        for log in _res.attributes.iter() {
            println!("key: {}, value: {}", log.key, log.value);
        }

        assert_eq!(_res.attributes[0].key, "verified");
        assert_eq!(_res.attributes[0].value, "true");
    }

    #[test]
    fn false_verification() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));
        let info = mock_info("creator", &coins(2, "token"));

        // Instantiate
        let _res = instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {}
        ).unwrap();

        let eth_address: Bytes20 = Bytes20::from(hex::decode("834AED40952Dd195ca2A5eB110E101E5461B5955").unwrap());
        let pubkey_x: Bytes32 = Bytes32::from(hex::decode("2b6ac5ee66c087425ceab6a4e78bcbbdda29829e1f0ba9ff0a35add28001244a").unwrap());

        // Add Group
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::AddGroup { eth_address, pubkey_x, pubkey_y_parity: 1u8 }
        ).unwrap();

        let req_id: MuonRequestId = MuonRequestId::from(hex::decode("0170122020a3a823f77a2ebef3fa130a6ff9a776225abd47a8997916af73cfaa7126299b").unwrap());
        let hash: Bytes32 = Bytes32::from(hex::decode("2d9fff2a7ab727ab3a0b82110e010fa1f0255381ea4e3bdfd2157c31836189ae").unwrap());
        let signature: Bytes32 = Bytes32::from(hex::decode("058cc5fdca29e04243490de0290cf517bf2d1d1556b61687040443179c964359").unwrap());
        let address: Bytes20 = Bytes20::from(hex::decode("834AED40952Dd195ca2A5eB110E101E5461B5955").unwrap());
        let nonce: Bytes20 = Bytes20::from(hex::decode("111134Af4fa82F852CF7c35fC8082B2e13E68404").unwrap());

        // Add Group
        let _res = execute(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            ExecuteMsg::VerifySignature { req_id, hash, sign: SchnorrSign { signature, address, nonce } }
        );

        assert!(_res.is_err());
        let msg: String = format!("{}", _res.unwrap_err());
        assert!(msg.contains("Not Verified"));
    }
}

