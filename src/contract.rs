#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Addr
};
use cw2::set_contract_version;

use crate::{
    error::ContractError,
    msg::{CountResponse, ExecuteMsg, InstantiateMsg, QueryMsg},
    state::{
        STATE,
        AdminInfo, ADMIN_INFO,
        GroupInfo, GROUP_INFO,
    },
    types::{SchnorrSign, MuonRequestId, Bytes20, Bytes32},
    utils::schnorr_verify
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:muon-cosmos";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    let admin_info = AdminInfo {
        admin: info.sender.clone(),
    };

    ADMIN_INFO.save(deps.storage, &admin_info)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
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
        } => try_verify_sign(deps, info, req_id, hash, sign),
    }
}

pub fn try_transfer_admin(deps: DepsMut, info: MessageInfo, new_admin: Addr) -> Result<Response, ContractError> {
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
    let group_info = GroupInfo {
        is_valid: true,
        eth_address: eth_address.clone(),
        pubkey_x: pubkey_x.clone(),
        pubkey_y_parity
    };
    GROUP_INFO.save(deps.storage, eth_address.clone(), &group_info);

    Ok(
        Response::new()
//            .add_attribute("method", "add_group")
//            .add_attribute("eth_address", hex::encode(eth_address))
//            .add_attribute("pubkey_x", hex::encode(pubkey_x))
//            .add_attribute("pubkey_y_parity", hex::encode([pubkey_y_parity]))
    )
}

pub fn try_verify_sign(
    deps: DepsMut,
    info: MessageInfo,
    req_id: MuonRequestId,
    hash: Bytes32,
    sign: SchnorrSign
) -> Result<Response, ContractError> {

    let group_info = GROUP_INFO.load(deps.storage, sign.address)?;

    let (is_verified, signer) = schnorr_verify(
        group_info.pubkey_x.0,
        group_info.pubkey_y_parity,
        sign.signature.0,
        hash.0,
        sign.nonce.0
    )?;

//    if !is_verified {
//        return Err(ContractError::NotVerified {});
//    }

    Ok(
        Response::new()
            .add_attribute("verified", if is_verified { "true" } else { "false" })
            .add_attribute("signer", signer.to_string())
            .add_attribute("group", hex::encode(group_info.eth_address.0))
    )
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetCount {} => to_binary(&query_count(deps)?),
    }
}

fn query_count(deps: Deps) -> StdResult<CountResponse> {
    let state = STATE.load(deps.storage)?;
    Ok(CountResponse { count: state.count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies_with_balance, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};

    #[test]
    fn verify() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));
        let info = mock_info("creator", &coins(2, "token"));

        // Instantiate
        let _res = instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg { count: 17 }
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

        // should increase counter by 1
//        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
//        let value: CountResponse = from_binary(&res).unwrap();
//        assert_eq!(17, 17);
    }

//    #[test]
//    fn proper_initialization() {
//        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));
//
//        let msg = InstantiateMsg { count: 17 };
//        let info = mock_info("creator", &coins(1000, "earth"));
//
//        // we can just call .unwrap() to assert this was a success
//        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
//        assert_eq!(0, res.messages.len());
//
//        // it worked, let's query the state
//        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
//        let value: CountResponse = from_binary(&res).unwrap();
//        assert_eq!(17, value.count);
//    }

//    #[test]
//    fn increment() {
//        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));
//
//        let msg = InstantiateMsg { count: 17 };
//        let info = mock_info("creator", &coins(2, "token"));
//        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
//
//        // beneficiary can release it
//        let info = mock_info("anyone", &coins(2, "token"));
//        let msg = ExecuteMsg::Increment {};
//        let _res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
//
//        // should increase counter by 1
//        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
//        let value: CountResponse = from_binary(&res).unwrap();
//        assert_eq!(18, value.count);
//    }
//
//    #[test]
//    fn reset() {
//        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));
//
//        let msg = InstantiateMsg { count: 17 };
//        let info = mock_info("creator", &coins(2, "token"));
//        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
//
//        // beneficiary can release it
//        let unauth_info = mock_info("anyone", &coins(2, "token"));
//        let msg = ExecuteMsg::Reset { count: 5 };
//        let res = execute(deps.as_mut(), mock_env(), unauth_info, msg);
//        match res {
//            Err(ContractError::Unauthorized {}) => {}
//            _ => panic!("Must return unauthorized error"),
//        }
//
//        // only the original creator can reset the counter
//        let auth_info = mock_info("creator", &coins(2, "token"));
//        let msg = ExecuteMsg::Reset { count: 5 };
//        let _res = execute(deps.as_mut(), mock_env(), auth_info, msg).unwrap();
//
//        // should now be 5
//        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
//        let value: CountResponse = from_binary(&res).unwrap();
//        assert_eq!(5, value.count);
//    }
}

