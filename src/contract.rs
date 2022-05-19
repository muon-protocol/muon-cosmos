#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Addr};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{CountResponse, ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{
    STATE,
    AdminInfo, ADMIN_INFO,
    GroupInfo, GROUP_INFO,
};
use crate::types::{SchnorrSign, Bytes20, Bytes32};

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

//pub fn try_increment(deps: DepsMut) -> Result<Response, ContractError> {
//    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
//        state.count += 1;
//        Ok(state)
//    })?;
//
//    Ok(Response::new().add_attribute("method", "try_increment"))
//}

//pub fn try_reset(deps: DepsMut, info: MessageInfo, count: i32) -> Result<Response, ContractError> {
//    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
//        if info.sender != state.owner {
//            return Err(ContractError::Unauthorized {});
//        }
//        state.count = count;
//        Ok(state)
//    })?;
//    Ok(Response::new().add_attribute("method", "reset"))
//}

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
    req_id: Bytes32,
    hash: Bytes32,
    sign: SchnorrSign
) -> Result<Response, ContractError> {
    Ok(Response::new())
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
    fn proper_initialization() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(17, value.count);
    }

    #[test]
    fn increment() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Increment {};
        let _res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // should increase counter by 1
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(18, value.count);
    }

    #[test]
    fn reset() {
        let mut deps = mock_dependencies_with_balance(&coins(2, "token"));

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let unauth_info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let res = execute(deps.as_mut(), mock_env(), unauth_info, msg);
        match res {
            Err(ContractError::Unauthorized {}) => {}
            _ => panic!("Must return unauthorized error"),
        }

        // only the original creator can reset the counter
        let auth_info = mock_info("creator", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let _res = execute(deps.as_mut(), mock_env(), auth_info, msg).unwrap();

        // should now be 5
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: CountResponse = from_binary(&res).unwrap();
        assert_eq!(5, value.count);
    }
}
