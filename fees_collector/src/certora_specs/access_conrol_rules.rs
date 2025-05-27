

use access_control::access::{AccessControlTrait};
use access_control::management::{MultipleAddressesManagementTrait, SingleAddressManagementTrait};
use access_control::role::{Role, SymbolRepresentation};
use access_control::storage::{DataKey, StorageTrait};
use access_control::transfer::TransferOwnershipTrait;
use crate::certora_specs::asaf_utils::get_transfer_deadline;
use crate::certora_specs::util::{get_role_safe_address, is_role};
use crate::certora_specs::asaf_utils::access_control_funcs::{nondet_func, Action};
use soroban_sdk::{Address, Env, Vec};
use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::{clog, cvlr_satisfy, nondet};
use cvlr_soroban::{nondet_address, nondet_vec};
use cvlr_soroban_derive::rule;

use super::asaf_utils::nondet_role;
use super::ACCESS_CONTROL;

/**
 * Rules for the access control crate
 * 
 * Key Players:
 *      deadline
 *      all datakeys
 *      Access_Control
 *      user add
 *      contract add
 *      
 */

// example for unit test rule for access control
#[rule]
pub fn set_emergency_mode_success(e: Env) {
    let value: bool = cvlr::nondet();
    access_control::emergency::set_emergency_mode(&e, &value);
    cvlr_assert!(access_control::emergency::get_emergency_mode(&e) == value);
}
/** 
 *  RULE: -- 
 *      Emergency mode changed => set_emergency_mode called 
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn emergency_mode_changed_due_to_set_emergency_mode(e: Env){

    let mode_before = access_control::emergency::get_emergency_mode(&e);

    let action  =  nondet_func(e.clone());

    let mode_after = access_control::emergency::get_emergency_mode(&e);

    cvlr_assume!(mode_before != mode_after);

    cvlr_assert!(action ==  Action::SetEmergencyMode);
}


/** 
 *  RULE: -- Maybe redundant. delet
 *      role.has_many_user => role is emergency pause admin
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_has_many_users_role_is_emergency_pause_admin(e: Env){
    let role = nondet_role();
    clog!(role.to_string());
    clog!(role.has_many_users());
    cvlr_assume!(role.has_many_users());
    cvlr_assert!(role.as_symbol(&e) == Role::EmergencyPauseAdmin.as_symbol(&e));

}

/** 
 *  RULE: 
 *      role.has_many_user => get_role_safe reverts
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_has_many_users_get_role_safe_reverts(){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    clog!(role.to_string());

    cvlr_assume!(role.has_many_users());

    acc_ctrl.get_role_safe(&role);

    cvlr_assert!(false); //shouldnt reach

}

/** 
 *  RULE: 
 *      role.as_symbol reverts for admin
 *  Tested: https://prover.certora.com/output/7145022/e4af4ddd67674695897f92ddb7009138/?anonymousKey=4cafd86165667bd2cb43bdb20fd6bd4056fe2e7c&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: rule passes, therefore, from_symbol is unreachable
 *  Note: 
 *       
*/
#[rule]
pub fn role_from_symbol_reverts_for_admin(e: Env){

    Role::from_symbol(&e, Role::Admin.as_symbol(&e));

    cvlr_assert!(false); //shouldnt reach
}

/** 
 *  RULE: 
 *      role.has_many_user => get_role_address reverts
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_has_many_users_get_role_reverts(){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    clog!(role.to_string());

    cvlr_assume!(role.has_many_users());

    acc_ctrl.get_role(&role);
    cvlr_assert!(false); //shouldnt reach

}

/** 
 *  RULE: 
 *      role.has_many_user => set_role_address reverts
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_has_many_users_set_role_address_reverts(){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    clog!(role.to_string());

    cvlr_assume!(role.has_many_users());

    acc_ctrl.set_role_address(&role, &nondet_address());

    cvlr_assert!(false); //shouldnt reach

}

/** 
 *  RULE: 
 *      !role.has_many_user => set_role_addresses reverts
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_not_has_many_users_set_role_addresses_reverts(){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    clog!(role.to_string());
   
    cvlr_assume!(!role.has_many_users());
    
    acc_ctrl.set_role_addresses(&role, &nondet_vec());

    cvlr_assert!(false); //shouldnt reach

}

/** 
 *  RULE: 
 *      !role.has_many_user => get_role_addresses reverts
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_not_has_many_users_get_role_addresses_reverts(){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    clog!(role.to_string());
   
    cvlr_assume!(!role.has_many_users());
    
    acc_ctrl.get_role_addresses(&role);

    cvlr_assert!(false); //shouldnt reach

}

/** 
 *  RULE: -- 
 *      future address changed => deadline changed
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn future_add_changed_deadline_changed(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let future_before = acc_ctrl.get_future_address(&role) ;
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    nondet_func(e.clone());

    let future_after = acc_ctrl.get_future_address(&role) ;
    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(future_before != future_after);

    cvlr_assert!(deadline_before != deadline_after);

}

/** 
 *  RULE: -- 
 *      future address changed => commit was called
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn future_add_changed_due_to_commit(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let future_before = acc_ctrl.get_future_address(&role) ;

    let action = nondet_func(e.clone());

    let future_after = acc_ctrl.get_future_address(&role) ;

    cvlr_assume!(future_before != future_after);

    cvlr_assert!(action ==  Action::CommitTransferOwnership);

}

/** 
 *  RULE: -- 
 *      deadline changed to nonzero => commit or put_transfer_deadline called
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn deadline_changed_to_nonzero_commit_or_put_transfer_deadline(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    let action = nondet_func(e.clone());

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(deadline_before != deadline_after && deadline_after>0);

    cvlr_assert!(action == Action::CommitTransferOwnership || action == Action::PutTransferOwnershipDeadline);

}

/** 
 *  RULE: -- 
 *      deadline changed to zero => revert, apply or put_transfer_deadline 
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn deadline_changed_to_zero_revert_apply_or_put_transfer_deadline(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    let action = nondet_func(e.clone());

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(deadline_before != deadline_after && deadline_after==0);

    cvlr_assert!(   action == Action::ApplyTransferOwnership || 
                    action == Action::PutTransferOwnershipDeadline ||
                    action == Action::RevertTransferOwnership);

}


/** 
 *  RULE: -- 
 *      deadline can only change to > now() or zero
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn deadline_valid_states_access_control(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    nondet_func(e.clone());

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(deadline_before != deadline_after && deadline_after==0);

    cvlr_assert!( deadline_after == 0 || deadline_after > e.ledger().timestamp());

}

/** 
 *  RULE: -- 
 *      Deadline != 0 => commit reverts
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn cant_commit_if_deadline_nonzero(){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let deadline = acc_ctrl.get_transfer_ownership_deadline(&role);
    cvlr_assume!(deadline != 0);
    
    acc_ctrl.commit_transfer_ownership(&role, &nondet_address());

    cvlr_assert!(false); // shoudlnt reach

}

/** 
 *  RULE: -- 
 *      Now() < deadline or role address is none => apply reverts
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn cant_apply_before_deadline(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let deadline = acc_ctrl.get_transfer_ownership_deadline(&role);
    cvlr_assume!(e.ledger().timestamp() < deadline && get_role_safe_address(role.clone()).is_some());
    clog!(role.to_string());
    clog!(e.ledger().timestamp());
    clog!(deadline);

    let address = acc_ctrl.apply_transfer_ownership(&role);
    clog!(cvlr_soroban::Addr(&address));


    cvlr_assert!(false); // shoudlnt reach

}


/** 
 *  RULE: -- 
 *      role address changed => new address == future address 
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_changed_future_address_is_new_address(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let address_before = acc_ctrl.get_role_safe(&role);
    let future_add = acc_ctrl.get_future_address(&role);


    let action  = nondet_func(e.clone());
    cvlr_assume!(   action != Action::SetRoleAddress ||
                    action != Action::SetRoleAddress);

    let address_after= acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!( address_after.unwrap() == future_add);

}

/** 
 *  RULE: -- 
 *      Role cant change to None
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_cant_change_to_none(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let address_before = acc_ctrl.get_role_safe(&role);

    nondet_func(e.clone());

    let address_after= acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!( address_after.is_some());

}

/** 
 *  RULE: -- 
 *      Role changed => role is either Admin or EmergencyAdmin unless using set_role_address
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_changed_is_admin_emergency_admin(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let address_before = acc_ctrl.get_role_safe(&role);
    clog!(role.to_string());

    let action = nondet_func(e.clone());

    let address_after= acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!(   action != Action::SetRoleAddress || 
                    action != Action::SetRoleAddresses ||
                    role.as_symbol(&e) == Role::Admin.as_symbol(&e) || role.as_symbol(&e) == Role::EmergencyAdmin.as_symbol(&e));

}

/** 
 *  RULE: -- 
 *      Role changed => role is transfer delay, unless some called set_role..
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_changed_is_transfer_delay(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let address_before = acc_ctrl.get_role_safe(&role);

    let action = nondet_func(e.clone());

    let address_after= acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!(   action != Action::SetRoleAddress || 
                    action != Action::SetRoleAddresses ||
                    role.is_transfer_delayed());

}

/** 
 *  RULE: 
 *      role.transfer delay => !role.has_many_users
 *  Tested: Yes.  
 *  Bugs: No
 *  Note: validated by changing admin has many users
*/
#[rule]
pub fn role_has_transfer_delay_has_one_user(){
    let role = nondet_role();

    cvlr_assume!(role.is_transfer_delayed());
    cvlr_assert!(!role.has_many_users());
}

/** 
 *  RULE: --  Might fail. maybe add set role addresses???
 *      Role changed => apply was called or set_role_address
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn role_changed_due_to_apply_or_set_role(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let address_before = acc_ctrl.get_role_safe(&role);

    let action = nondet_func(e.clone());

    let address_after= acc_ctrl.get_role_safe(&role);

    cvlr_assume!(address_before != address_after);

    cvlr_assert!( action == Action::ApplyTransferOwnership || action == Action::SetRoleAddress);

}

/** 
 *  RULE: -- 
 *      Transfering a role doesnt affect the other roles
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn one_role_at_a_time(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let other_role = nondet_role();

    cvlr_assume!(role.as_symbol(&e) != other_role.as_symbol(&e));

    let address_before = acc_ctrl.get_role_safe(&role);
    let other_address_before = acc_ctrl.get_role_safe(&other_role); 

    nondet_func(e.clone());

    let address_after= acc_ctrl.get_role_safe(&role);
    let other_address_after = acc_ctrl.get_role_safe(&other_role);

    cvlr_assume!(address_before != address_after);
    cvlr_assert!(other_address_before == other_address_after);

}

/** 
 *  RULE: 
 *      Admin can transfer his role
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn admin_can_transfer_his_role(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  Role::Admin;
    let address_before = acc_ctrl.get_role_safe(&role);

    nondet_func(e.clone());

    let address_after= acc_ctrl.get_role_safe(&role);

    cvlr_satisfy!(address_before != address_after);

}

/** 
 *  RULE: 
 *      Emergency Admin can transfer his role
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn emergency_admin_can_transfer_his_role(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  Role::EmergencyAdmin;
    let address_before = acc_ctrl.get_role_safe(&role);

    nondet_func(e.clone());

    let address_after= acc_ctrl.get_role_safe(&role);

    cvlr_satisfy!(address_before != address_after);

}

/**
 * UNIT TESTS
 */

/** 
 *  RULE: --  address_has_role integrity
 *  Tested: No
 *  Bugs: Yes
 *  Note:   Doesnt work for roles with many users because the .contains method for vectors
 *          in soroban sdk is not implemented. As per https://discord.com/channels/795999272293236746/1375030757013192795
 *       
*/
 #[rule]
 pub fn address_has_role_integrity(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    let address = nondet_address();
    clog!(role.has_many_users());

    if role.has_many_users(){
        cvlr_assume!(e.storage().instance().get(&role_key).unwrap_or(Vec::<Address>::new(&e)).contains(&address));
        cvlr_assert!(acc_ctrl.address_has_role(&address, &role));
    }
    else {
        cvlr_assume!(address == e.storage().instance().get(&role_key).unwrap());
        cvlr_assert!(acc_ctrl.address_has_role(&address, &role)); 
    }


 }

/** 
 *  RULE: --  get_role_safe integrity
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
 #[rule]
 pub fn get_role_safe_integrity(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    let address = acc_ctrl.get_role_safe(&role);
    clog!(role.to_string());

    cvlr_assert!(address == e.storage().instance().get(&role_key)); 

 }

 /** 
 *  RULE: -- get_role integrity
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
  #[rule]
 pub fn get_role_integrity(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    let address = acc_ctrl.get_role(&role);
    clog!(role.to_string());
    
    match e.storage().instance().get::<DataKey, Address>(&role_key){
        Some(add) => cvlr_assert!(address == add),
        None => cvlr_assert!(false) // shouldnt reach here.
        
    }
    let true_value = e.storage().instance().get::<DataKey, Address>(&role_key).unwrap();

    cvlr_assert!(address == true_value);
 }

  /** 
 *  RULE: -- set_role_address integrity
 *  Tested: No
 *  Bugs: No
 *  Note:   Can be used to set any role. 
 *          If role is not set yet, it doesnt matter which role it is (no has_many_users)
 *          If role is set, then we cant use this function if is_transfer_delayed
 *       
*/

   #[rule]
 pub fn set_role_address_integrity(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    let current = acc_ctrl.get_role_safe(&role);
    let address_to_set = nondet_address();

    acc_ctrl.set_role_address(&role, &address_to_set);

    cvlr_assert!(!role.has_many_users() && e.storage().instance().get::<DataKey, Address>(&role_key).unwrap() == address_to_set &&
                    ((current.is_some() && !role.is_transfer_delayed()) || (current.is_none()))) 
 }

 // Passed
#[rule]
 pub fn get_role_addresses_integrity(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    clog!(role.to_string());

    let get_value = acc_ctrl.get_role_addresses(&role);
    let true_value = e.storage().instance().get::<DataKey, Vec<Address>>(&role_key).unwrap();

    cvlr_assert!(role.has_many_users() &&  get_value == true_value);

 }

#[rule]
 pub fn set_role_addresses_integrity(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let role_key: DataKey = acc_ctrl.get_key(&role);
    let addresses_to_set = nondet_vec::<Address>();
    
    acc_ctrl.set_role_addresses(&role, &addresses_to_set);

    let true_address = e.storage().instance().get::<DataKey, Vec<Address>>(&role_key).unwrap();
    cvlr_assert!(role.has_many_users() && addresses_to_set == true_address);

 }

#[rule]
pub fn get_emergency_mode_integrity_access_control(e: Env) {
    let value: bool = access_control::emergency::get_emergency_mode(&e);
    let emergency_mode_key = DataKey::EmergencyMode;
    cvlr_assert!(e.storage().instance().get::<DataKey, bool>(&emergency_mode_key).unwrap() == value);
}

#[rule]
pub fn require_rewards_admin_or_owner_integrity(e: Env) {
    let address: Address = nondet_address();

    access_control::utils::require_rewards_admin_or_owner(&e, &address);

    cvlr_assert!(is_role(&address, &Role::Admin) || is_role(&address, &Role::RewardsAdmin));
}

#[rule]
pub fn require_operations_admin_or_owner_integrity(e: Env) {
    let address = nondet_address();

    access_control::utils::require_operations_admin_or_owner(&e, &address);

    cvlr_assert!(is_role(&address, &Role::Admin) || is_role(&address, &Role::OperationsAdmin));
}

  /** 
 *  RULE: -- require_pause_or_emergency_pause_admin_or_owner integrity
 *  Tested: No
 *  Bugs: Yes
 *  Note: FAILS for emergency pause admin due to issue with Vec<Address>.contain implimentation
 *          as per: https://discord.com/channels/795999272293236746/1375030757013192795
 *       
*/
#[rule]
pub fn require_pause_or_emergency_pause_admin_or_owner_integrity(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));

    
    access_control::utils::require_pause_or_emergency_pause_admin_or_owner(&e, &address);
    
    clog!(is_role(&address, &Role::EmergencyPauseAdmin));
    clog!(is_role(&address, &Role::PauseAdmin));
    clog!(is_role(&address, &Role::Admin));

    let true_pause_admin = e.storage().instance().get::<DataKey, Address>(&DataKey::PauseAdmin).unwrap();
    let true_emergency_pause_admin = e.storage().instance().get::<DataKey, Vec<Address>>(&DataKey::EmPauseAdmins).unwrap_or(Vec::new(&e));
    let true_admin = e.storage().instance().get::<DataKey, Address>(&DataKey::Admin).unwrap();

    let is_emergency_admin = true_emergency_pause_admin.contains(&address);

    cvlr_assert!(   address == true_admin ||
                    address == true_pause_admin ||
                    is_emergency_admin);
}

#[rule]
pub fn require_pause_admin_or_owner_integrity(e: Env) {
    let address = nondet_address();

    access_control::utils::require_pause_admin_or_owner(&e, &address);

    cvlr_assert!(is_role(&address, &Role::Admin) || is_role(&address, &Role::PauseAdmin));
}

/** 
 *  RULE: --  assert_address_has_role_integrity
 *  Tested: https://prover.certora.com/output/7145022/6864340e23f9498eb240b8a9e2514364/?anonymousKey=992a113decc8fb3927b32c562c142e7bb08ad242&params=%7B%222%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A2%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%222-10-1-02-1-1-1-1-1-1-1-1%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: Yes
 *  Note:   Doesnt work for roles with many users because the .contains method for vectors
 *          in soroban sdk is not implemented. As per https://discord.com/channels/795999272293236746/1375030757013192795
 *       
*/
#[rule]
pub fn assert_address_has_role_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let address = nondet_address();
    let role = nondet_role();
    let role_key = acc_ctrl.get_key(&role);
    clog!(role.has_many_users());
    acc_ctrl.assert_address_has_role(&address, &role);

    cvlr_assert!((!role.has_many_users() && address == e.storage().instance().get::<DataKey, Address>(&role_key).unwrap()) ||
                 (role.has_many_users() && e.storage().instance().get::<DataKey, Vec<Address>>(&role_key).unwrap_or(Vec::new(&e)).contains(&address)));
}

#[rule]
pub fn commit_transfer_ownership_integrity_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let future_address = nondet_address();
    let role = nondet_role();
    let future_role_key = acc_ctrl.get_future_key(&role);

    acc_ctrl.commit_transfer_ownership(&role, &future_address);

    cvlr_assert!(future_address == e.storage().instance().get::<DataKey, Address>(&future_role_key).unwrap() &&
                get_transfer_deadline(&role) == e.ledger().timestamp() + access_control::constants::ADMIN_ACTIONS_DELAY &&
                role.is_transfer_delayed() && !role.has_many_users());
}

#[rule]
pub fn apply_transfer_ownership_integrity_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let current_address = acc_ctrl.get_role_safe(&role);
    let future_address = acc_ctrl.get_future_address(&role);
    let role_key = acc_ctrl.get_future_key(&role);
    let deadline_before =  acc_ctrl.get_transfer_ownership_deadline(&role);

    let returned_address = acc_ctrl.apply_transfer_ownership(&role);

    let deadline_after =  acc_ctrl.get_transfer_ownership_deadline(&role);
    cvlr_assert!((
                future_address == e.storage().instance().get::<DataKey, Address>(&role_key).unwrap() &&
                returned_address == future_address) && 
                ((current_address.is_some() && deadline_after == 0 && deadline_before <= e.ledger().timestamp()) ||
                ( current_address.is_none() && deadline_after == 0 )));
}

#[rule]
pub fn revert_transfer_ownership_integrity_access_control() {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();

    acc_ctrl.revert_transfer_ownership(&role);

    cvlr_assert!(get_transfer_deadline(&role) == 0);
}

#[rule]
pub fn get_future_address_integrity_access_control(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let future_role_key = acc_ctrl.get_future_key(&role);

    cvlr_assert!(acc_ctrl.get_future_address(&role) == e.storage().instance().get::<DataKey, Address>(&future_role_key).unwrap());
}

#[rule]
pub fn put_transfer_ownership_deadline_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline_key = acc_ctrl.get_future_deadline_key(&role);
    let value = nondet();
    acc_ctrl.put_transfer_ownership_deadline(&role, value);

    cvlr_assert!(value == e.storage().instance().get::<DataKey, u64>(&deadline_key).unwrap());
}

#[rule]
pub fn get_transfer_ownership_deadline_integrity(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role = nondet_role();
    let deadline_key = acc_ctrl.get_future_deadline_key(&role);
    let get_deadline = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assert!(get_deadline == e.storage().instance().get::<DataKey, u64>(&deadline_key).unwrap()     );
}