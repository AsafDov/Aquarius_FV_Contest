
// use core::ops::Add;
// use core::{clone, future};

// use access_control::emergency;
// use soroban_sdk::deploy::DeployerWithAddress;
// use soroban_sdk::xdr::Value;

use access_control::transfer::TransferOwnershipTrait;
use cvlr::clog;
use soroban_sdk::{Address, Env};
use access_control::interface::TransferableContract;
use access_control::storage::{ StorageTrait};
use access_control::role::{Role, SymbolRepresentation};
use access_control::access::AccessControl;

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::{cvlr_satisfy, nondet};
use cvlr_soroban::{is_auth, nondet_address};
use cvlr_soroban_derive::rule;

use crate::certora_specs::util::{get_role_address, is_role,get_role_safe_address};
use crate::certora_specs::ACCESS_CONTROL;
pub use crate::contract::FeesCollector;
use crate::interface::AdminInterface;
use upgrade::interface::UpgradeableContract;
use upgrade::storage::{get_future_wasm };
use upgrade::storage::get_upgrade_deadline;
use upgrade::storage::DataKey;

use crate::certora_specs::asaf_utils::{nondet_role, nondet_wasm,get_transfer_deadline};
use crate::certora_specs::asaf_utils::fees_collector_funcs::{nondet_func, Action};

/**
 * These are some example rules to help get started.
*/

#[rule]
pub fn init_admin_sets_admin(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    FeesCollector::init_admin(e, address.clone());
    let addr = get_role_address(Role::Admin);
    // syntax of how to use `clog!`. This is helpful for calltrace when a rule fails.
    clog!(cvlr_soroban::Addr(&addr));
    cvlr_assert!(addr == address);
    cvlr_assert!(is_role(&addr, &Role::Admin))
}

#[rule]
pub fn only_emergency_admin_sets_emergency_mode(e: Env) {
    let address = nondet_address();
    let value: bool = cvlr::nondet();
    cvlr_assume!(!is_role(&address, &Role::EmergencyAdmin));
    FeesCollector::set_emergency_mode(e, address, value);
    cvlr_assert!(false); // should not reach and therefore should pass
}



/**
 * END example rules 
 */

/** 
 *  RULE: -- 
 *      Emergency mode changed => Emergency Admin isnt None
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn emergency_mode_changed_emergency_admin_is_some(e: Env){

    let mode_before = FeesCollector::get_emergency_mode(e.clone());

    nondet_func(e.clone());

    let mode_after = FeesCollector::get_emergency_mode(e.clone());

    cvlr_assume!(mode_before != mode_after);

    cvlr_assert!(get_role_safe_address(Role::EmergencyAdmin).is_some());
}
/**
 * ROLE TRANSFER LOGIC 
 */

/** State Transition -- !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *  RULE: 
 *      if future address changed => someone called commit
 *  Tested: Yes
 *  Bugs: Yes. get_emergency() again????
 *  Note:   When accessed get future role for feescollector and then through access control, it fails
 *          but when both accessed from access_control - the rule passes
 *          when both are accessed from feescollector? --
*/
#[rule]
pub fn future_address_state_transition(e: Env){
    let role = nondet_role();

    //let future_address_before = access_control.get_future_address(&role); -works
    let future_address_before = FeesCollector::get_future_address(e.clone(),role.as_symbol(&e));
    clog!(cvlr_soroban::Addr(&future_address_before));
    clog!(is_role(&future_address_before, &role));
    
    // // Perform action
    let func = nondet_func(e.clone());

    let future_address_after = FeesCollector::get_future_address(e.clone(),role.as_symbol(&e));
    clog!(cvlr_soroban::Addr(&future_address_after));
    clog!(is_role(&future_address_after, &role));

    // Assume future address changed after the operation
    cvlr_assume!(future_address_before != future_address_after );
    clog!(func==Action::CommitTransfer);

    // Assert the only operation that changed it is the commit transfer
    cvlr_assert!(func == Action::CommitTransfer);

} 

/** 
 *  RULE: 
 *      If some changed from being an admin, he can always go back to being admin
 *      -- This rule is to see if theres a way transfer Admin to contract address,
 *      which I am not sure can perform actions
 *  Tested: Yes
 *  Bugs: No
 *  Note:   Lacking safty feature. Contract connot authorize itself, nor invoke functions. Should have been caught here
 *          However, the feature is found missing. Should be corrected with an approve function to require auth of address
 *          to whom the role is being transfered to. This also includes Init_Admin funtion.
*/
#[rule]
pub fn user_changed_from_role_can_become_role_again(e: Env){
    let user = nondet_address();
    let role = nondet_role();
    clog!(cvlr_soroban::Addr(&user));
    cvlr_assume!(is_role(&user, &role));

    FeesCollector::commit_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e), nondet_address());
    FeesCollector::apply_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));

    //cvlr_assume!(!is_role(&user, &role));
    clog!(is_role(&user, &role));

    FeesCollector::commit_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e), user.clone());
    FeesCollector::apply_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));

    cvlr_assert!(is_role(&user, &role));
}

/** --state transition
 *  RULE: 
 *      Role changed => apply transfer was called or InitAdmin was called if role was none. (implment for upgrade as well)
 *  Tested: Yes
 *  Bugs: No
 *  Note: 
*/
#[rule]
pub fn role_only_changes_if_apply_transfer(e: Env){
    let role = nondet_role();
    let address_before = get_role_safe_address(role.clone());

    // Execute operation
    let action = nondet_func(e.clone());

    let address_after = get_role_safe_address(role.clone());

    cvlr_assume!(address_before != address_after);

    cvlr_assert!(action==Action::ApplyTransfer ||  (address_before.is_none() && action == Action::InitAdmin));
}

/** 
 *  RULE: 
 *      Deadline changed to nonzero value => commit was called 
 *  Tested: Yes
 *  Bugs: No
 *  Reason: 
*/
#[rule]
pub fn deadline_changed_due_to_commit(e: Env){
    let role = nondet_role();
    let deadline_before= get_transfer_deadline(&role);

    //Execute Operation
    let action = nondet_func(e.clone());

    let deadline_after= get_transfer_deadline(&role);

    // assume deadline changed to nonzero value
    cvlr_assume!(deadline_before != deadline_after && deadline_after>0);

    cvlr_assert!(action == Action::CommitTransfer);
}


/** 
 *  RULE: 
 *      apply transfer called => revert does nothing 
 *  Tested: Yes
 *  Bugs: No
 *  Reason: 
*/
#[rule]
pub fn cant_revert_transfer_if_apply_called(e: Env){
    let future_add = nondet_address();
    let role = nondet_role();

    //Assume the future add is not the role yet
    cvlr_assume!(!is_role(&future_add, &role));
    FeesCollector::apply_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));
    
    //Assume he became role after the apply
    cvlr_assume!(is_role(&future_add, &role));

    //Try to revert -- Doesnt panic
    FeesCollector::revert_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));

    //Role stays with future add
    cvlr_assert!(is_role(&future_add, &role));
}

/** 
 *  RULE: 
 *      if revert => apply does nothing
 *  Passed: 
 *  Verified:
 *  Bugs: No
 *  Note: 
*/
#[rule]
pub fn cant_apply_transfer_if_revert_called(e:Env){   
    let role = nondet_role();

    FeesCollector::revert_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));
    FeesCollector::apply_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));
    
    cvlr_assert!(false); // shouldnt reach 
}

/** 
 *  RULE: 
 *      Deadline changed to zero value => apply or revert was called 
 *  Tested: Yes
 *  Bugs: No
 *  Reason: 
*/
#[rule]
pub fn deadline_changed_due_to_revert_or_apply(e: Env){
    let role = nondet_role();
    let deadline_before= get_transfer_deadline(&role);

    //Execute Operation
    let action = nondet_func(e.clone());

    let deadline_after= get_transfer_deadline(&role);

    // assume deadline changed to nonzero value
    cvlr_assume!(deadline_before != deadline_after && deadline_after==0);

    cvlr_assert!(action == Action::ApplyTransfer || action == Action::RevertTransfer);
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
pub fn deadline_valid_states_fees_collector(e: Env){
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL }.as_ref().unwrap();
    let role =  nondet_role();
    let deadline_before = acc_ctrl.get_transfer_ownership_deadline(&role);

    nondet_func(e.clone());

    let deadline_after = acc_ctrl.get_transfer_ownership_deadline(&role);

    cvlr_assume!(deadline_before != deadline_after && deadline_after==0);

    cvlr_assert!( deadline_after == 0 || deadline_after > e.ledger().timestamp());

}

/** 
 *  RULE: 
 *      role transfered after apply =>  delay < blocktimestamp 
 *  Passed Test: https://prover.certora.com/output/7145022/f9ec987ad45a45cdaf4d31fcec6ac06d/?anonymousKey=92280f4d57bf53a92c55bc7b84f8ead3f430e5df&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Validation Test: https://prover.certora.com/output/7145022/401e5593773f49569b6307fdd423701f/?anonymousKey=142058a38145e13da5254ae94d99a6a2a2efa3e8&params=%7B%222%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A2%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%222-10-1-02-1-1-1-1-1-1-1-1%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: No
 *  Note: Tested by asserting delay < e.ledger().timestamp() rather than ">="
*/
#[rule]
pub fn role_cant_transfer_within_deadline(e: Env){
    let role = nondet_role();
    
    let address_before = get_role_safe_address(role.clone());
    let delay = get_transfer_deadline(&role);
    clog!(cvlr_soroban::Addr(&address_before.as_ref().unwrap()));
    clog!(delay);

    // Assume a delay is set, someone called commit
    cvlr_assume!(delay>0);

    // Execute apply
    FeesCollector::apply_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e));
    
    let address_after = get_role_safe_address(role.clone());
    clog!(cvlr_soroban::Addr(&address_after.as_ref().unwrap()));
    
    // assume role transfered
    cvlr_assume!(address_before != address_after);
    clog!(e.ledger().timestamp());

    cvlr_assert!(delay <= e.ledger().timestamp());  

}

/** 
 *  RULE: 
 *      If I am an Admin, I can transfer my role 
 *  Passed Test: No
 *  Validation Test: https://prover.certora.com/output/7145022/422d3ad3c1ea4cfb9749fb8078a01750/?anonymousKey=8a436a90564e31a4f7215aa64ba98d850821f4b8&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: YES - admin cannot transfer his role to anyone due to Role::from_symbol bug
 *  Note: 
*/
#[rule]
pub fn admin_can_transfer(e: Env){
    let role = Role::Admin;

    let address_before = get_role_safe_address(role.clone());
    
    let action = nondet_func(e.clone());
    cvlr_assume!(action != Action::InitAdmin);

    let address_after = get_role_safe_address(role.clone());
    
    cvlr_satisfy!(address_before != address_after);
}

/** 
 *  RULE: 
 *      If I am an Emergency admin, I can transfer my role 
 *  Passed Test:
 *  Validation Test:
 *  Bugs: No
 *  Note: 
*/
#[rule]
pub fn emergency_admin_can_transfer(e: Env){
    let role = Role::EmergencyAdmin;

    let address_before = get_role_safe_address(role.clone());
    
    let action = nondet_func(e.clone());
    cvlr_assume!(action != Action::InitAdmin);

    let address_after = get_role_safe_address(role.clone());
    
    cvlr_satisfy!(address_before != address_after);
}

/** 
 *  RULE: 
 *      if role had address => cant transfer role to None 
 *  Passed Test:
 *  Validation Test:
 *  Bugs: No
 *  Note: Rule shows vacuity for address after == None
*/

#[rule]
pub fn cant_transfer_role_to_none(e: Env){
    let role = nondet_role();
    clog!(role.to_string());
    
    let address_before = get_role_safe_address(role.clone());

    cvlr_assume!(address_before.is_some());
    
    nondet_func(e.clone());
    //cvlr_assume!(action != Action::InitAdmin);

    let address_after = get_role_safe_address(role.clone());
    
    cvlr_assume!(address_after.is_none());
    cvlr_assert!(false); // Shouldnt reach due to vacuity, should pass
}


/** 
 *  RULE: 
 *      if role has deadline => role.is_transfer_delayed
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn role_has_deadline_is_transfer_delayed(){

    let role = nondet_role();
    //let role = Role::Admin;
    get_transfer_deadline(&role);

    cvlr_assert!(role.is_transfer_delayed()); 
}

/** 
 *  RULE: 
 *      if role.is_transfer_delayed => role has deadline
 *          The other direction of the rule above
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn role_is_transfer_delayed_has_deadline(){

    let role = nondet_role();
    cvlr_assume!(!role.is_transfer_delayed());
    //let role = Role::Admin;
    get_transfer_deadline(&role);

    cvlr_assert!(false); // shoudlnt reach.

}


/** 
 *  RULE:  
 *      Deadline changed => (from 0 => deadlline>currenttimestamp)
 *                          (from deadline =! 0 => deadline = 0)   
 *  Passing test: https://prover.certora.com/output/7145022/4389bd079e294e6cb4afd7a4a025c8de/?anonymousKey=f9c41c589079e74f54a0fe42ef27cc7df6827145&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Atrue%2C%22fileViewCollapsed%22%3Afalse%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22file%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%22uiID%22%3A%225e0142%22%2C%22output%22%3A%22.certora_sources%2Ffees_collector%2Fsrc%2Fcertora_specs%2Ffee_collector_rules.rs%22%2C%22name%22%3A%22fee_collector_rules.rs%22%7D%2C%22fileViewFilter%22%3A%22fee%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%22677593%22%2C%22cc8692%22%2C%2292951d%22%2C%2217404f%22%2C%222f3e0b%22%2C%225c4625%22%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Validation test: https://prover.certora.com/output/7145022/b48256f2cfd24a24aa1d5cd6f540220f/?anonymousKey=ec154ff7d1ee78f91fdadc9b2de322c8d25a96c3&params=%7B%222%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%2212-10-1-1-1-1-1-010_12-1-1-1-1%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Atrue%2C%22fileViewCollapsed%22%3Afalse%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%22uiID%22%3A%225d9ea1%22%2C%22output%22%3A%22.certora_sources%2Ffees_collector%2Fsrc%2Fcertora_specs%2Ffee_collector_rules.rs%22%2C%22name%22%3A%22fee_collector_rules.rs%22%7D%2C%22fileViewFilter%22%3A%22fee%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A2%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%222-10-1-02-1-1-1-1-1-1-1-1%22%2C%22expandedFilesState%22%3A%5B%224d4d28%22%2C%2285fece%22%2C%22396952%22%2C%2236ce6c%22%2C%22d6ed68%22%2C%2268b424%22%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: No
 *  Note: validated by removing applyUpgrade
*/
#[rule]
pub fn deadline_state_transition_transfer(e: Env){
    
    let role = nondet_role();

    let deadline_before= get_transfer_deadline(&role);

    //Execute Operation
    nondet_func(e.clone());

    let deadline_after= get_transfer_deadline(&role);

    //assume deadline changed
    cvlr_assume!(deadline_before != deadline_after);

    if deadline_before==0{
        cvlr_assert!(deadline_after>e.ledger().timestamp());
    }
    else{
        cvlr_assert!(deadline_after == 0);
    }

}

//----------------------------------------------------------------------------------//

/**
 *  RULE:
        Cant call init if theres already an Admin
    Tested: Yes.
    Bugs: No
    Note: 
*/
#[rule]
pub fn no_init_if_admin_exists(e: Env){
    let admin_address = get_role_safe_address(Role::Admin);
    cvlr_assume!(admin_address.is_some());
    FeesCollector::init_admin(e.clone(), nondet_address());
    cvlr_assert!(false); // Should never get here, so it must be true.
}


/** HIGH LEVEL
 *  RULE:
 *          Every role has only 1 address, unless has_many_users
 *  Note:   
 *    
 *  Tested: Yes. 
 *          Verified functionality by removing assumption 
 *          that role!=EmergencyPauseAdmin and expecting failure
 *          
 *  Bugs: No
*/
#[rule]
pub fn one_address_per_role(){
    let role = nondet_role();
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let other_address = nondet_address();
    clog!(cvlr_soroban::Addr(&other_address));
    
    cvlr_assume!(!role.has_many_users());

    // assume both addresses have the same role:
    cvlr_assume!(is_role(&address, &role) && is_role(&other_address, &role));

    cvlr_assert!(address==other_address);
}

/** 
 *  RULE: 
 *      Only Admin can call commit, apply, revert for transfer or upgrade
 *  Tested: Yes 
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn only_admin_transfers_roles_or_upgrades(e: Env){

    //Execute Operation
    let action = nondet_func(e.clone());
    cvlr_assume!(
        action ==  Action::CommitTransfer ||
        action ==  Action::ApplyTransfer  ||
        action ==  Action::RevertTransfer ||
        action ==  Action::CommitUpgrade  ||
        action ==  Action::ApplyUpgrade   ||
        action ==  Action::RevertUpgrade      
    );
        
    let admin = get_role_safe_address(Role::Admin);
    //If there is an Admin => he should be signer;
    //If there is no admin => commit could not have been done by the admin. 
    match admin{
        Some(admin) => {let is_auth = is_auth(admin);
                                cvlr_assert!(is_auth); },
        None => cvlr_assert!(false)
    }     
}

/** 
 *  RULE: 
 *      Role changed => Must be Only Admin or Emergency Admin.
 *  Tested: Yes
 *  Bugs: No
 *  Reason: 
*/
#[rule]
pub fn only_admin_or_emergency_admin_be_transfered(e: Env){
    
    let role = nondet_role();
    let add_before = get_role_safe_address(role.clone());
    
    //Exucute operation
    nondet_func(e.clone());

    let add_after = get_role_safe_address(role.clone());

    cvlr_assume!(add_after != add_before);

    cvlr_assert!(role.as_symbol(&e) == Role::Admin.as_symbol(&e) || 
                role.as_symbol(&e) == Role::EmergencyAdmin.as_symbol(&e));
}



/** 
 *  RULE: 
 *      Contract address cant have role. Its more important for Admin and Emergency Admin.
 *  Tested: Yes
 *  Verify: https://prover.certora.com/output/7145022/c30e151721274f519c65233d536028ed/?anonymousKey=fe5a5a7a856c03d9209db7b62bc15edc956f9155&params=%7B%222%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%2215-10-1-1-1-1-1-1-1-015-1-1%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A2%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%222-10-1-02-1-1-1-1-1-1-1-1%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: Yes
 *  Reason: 
 *      Contract can be assigned a role. Its a bug. Contract could lose functionality if 
 *      Admin and/or Emergency Admin are assinged to contract address.
*/
#[rule]
pub fn contract_cant_have_role(e: Env){
    let role = &nondet_role();
    let contract = e.current_contract_address();

    // Assume the contract has no role innitially
    cvlr_assume!(!is_role(&contract, &role));

    // Execute Operation
    nondet_func(e.clone());

    // Assert contract still has no role assigned. 
    //cvlr_assert!(!is_role(&contract, &role))
    cvlr_satisfy!(is_role(&contract, &role))
}   




/** 
 *  RULE: 
 *      Cannot commit if deadline > 0 
 *  Tested: Yes. Verified by assuming deadline >= 0 
 *  Bugs: No
 *  Note: 
*/
#[rule]
pub fn cant_commit_before_deadline_transfer(e: Env){
    let role = nondet_role();
    let deadline:u64 = get_transfer_deadline(&role);

    cvlr_assume!(deadline > 0);

    FeesCollector::commit_transfer_ownership(e.clone(), nondet_address(), role.as_symbol(&e), nondet_address());

    cvlr_assert!(false); // Should not reach -> should pass
}

/** 
 *  RULE: 
 *      Deadline changed => role.is_transfer_delayed
 *  Tested: Yes
 *  Bugs: No
 *  Note:  
*/
#[rule]
pub fn no_deadline_for_unauth_roles(e: Env){
    let role = nondet_role();
    
    let deadline_before:u64 = get_transfer_deadline(&role);

    // Execute Op
    nondet_func(e.clone());

    let deadline_after:u64 = get_transfer_deadline(&role);

    cvlr_assume!(deadline_after != deadline_before);

    cvlr_assert!(role.is_transfer_delayed())

    // cvlr_assert!(    role.is_transfer_delayed() && (
    //             role.as_symbol(&e) == Role::Admin.as_symbol(&e) ||
    //             role.as_symbol(&e) == Role::EmergencyAdmin.as_symbol(&e)));

}

/** 
 *  RULE: 
 *      emergency mode changed => Emergency admin called set emergency mode
 *  Tested: Yes
 *  Bugs: No
 *  Note:   
*/
#[rule]
pub fn emergency_mode_state_transition(e: Env){ 
    let emergency_admin = get_role_safe_address(Role::EmergencyAdmin);
    let emergency_mode_before = FeesCollector::get_emergency_mode(e.clone());

    let action = nondet_func(e.clone());

    let emergency_mode_after = FeesCollector::get_emergency_mode(e.clone());

    clog!(emergency_mode_before);
    clog!(emergency_mode_after);

    cvlr_assume!(emergency_mode_before != emergency_mode_after);

    match emergency_admin{
        Some(emerg_admin) => cvlr_assert!(action == Action::SetEmergencyMode && is_auth(emerg_admin)),
        None => cvlr_assert!(false) // Cant change emergency mode if theres no emergency admin
    }
    // cvlr_satisfy!(true); // check reachability
}

/*---------------------------------------------------------------------------------------------- */

/**
 * CONTRACT UPGRADE LOGIC
 */


/** 
 *  RULE: 
 * 
 *      if emergency mode => Admin apply upgrade without waiting on deadline
 *  Tested: Yes - verifyied by setting emergency mode false.
 *  Bugs: 
 *  Note:    
*/
#[rule]
pub fn no_upgrade_delay_if_emergency_mode(e: Env){ 
    let emergency_mode = FeesCollector::get_emergency_mode(e.clone());
    let new_wasm = nondet_wasm();

    // Set the new wasm in for the assertion
    upgrade::storage::put_future_wasm(&e, &new_wasm);
    let delay = get_upgrade_deadline(&e);
    
    // Should be the new wasm of the contract after apply
    let returned_wasm = FeesCollector::apply_upgrade(e.clone(), nondet_address());

    if emergency_mode{
        cvlr_assert!(delay>0 && new_wasm == returned_wasm)
    }
    else{
        cvlr_assert!(delay>0 && e.ledger().timestamp()>delay && new_wasm == returned_wasm);
    }
}

/** State Transition -- 
 *  RULE: 
 *      if future wasm changed => Admin called commit upgrade && didnt change to None.
 *      if one can set the future wasm to None, then apply, without proper defences, it might nullify
 *      the contract. 
 *      
 *  Tested: Yes. Validate by swithching commitupgrade to revertUpgrade
 *  Bugs: no
 *  Note:  Not checking for admin due to the only_admin_transfers_roles_or_upgrades rule
*/
#[rule]
pub fn future_wasm_state_transition(e: Env){

    let future_wasm_before = upgrade::storage::get_future_wasm(&e);
    
    // // Perform action
    let action = nondet_func(e.clone());

    let future_wasm_after = upgrade::storage::get_future_wasm(&e);

    // Assume future address changed after the operation
    cvlr_assume!(future_wasm_before != future_wasm_after );


    //Assert the only operation that changed it is the commit transfer
    match future_wasm_after {
        Some(_wasm) => cvlr_assert!(action == Action::CommitUpgrade),
        None => cvlr_assert!(false) // should not be none. 
    }

} 


/** 
 *  RULE: 
 *      Deadline changed to nonzero value => commitupgrade was called 
 *  Passing test: https://prover.certora.com/output/7145022/c5e0cc0654a04992bcb179acae65a237/?anonymousKey=177d2cb1f70bd1c2eefc11e150f07693b205c9ae&params=%7B%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3Anull%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Validation test: https://prover.certora.com/output/7145022/f158036095d54d47afdde7af0162b8ca/?anonymousKey=be64bc82e244d9dcd7b3efc61d4b286891f8a0ce&params=%7B%222%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A2%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%222-10-1-02-1-1-1-1-1-1-1-1%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: No
 *  Note: validated by changing CommitUpgrade to RevertUpgrade
*/
#[rule]
pub fn deadline_changed_due_to_commit_upgrade(e: Env){

    let deadline_before= get_upgrade_deadline(&e);

    //Execute Operation
    let action = nondet_func(e.clone());

    let deadline_after= get_upgrade_deadline(&e);

    // assume deadline changed to nonzero value
    cvlr_assume!(deadline_before != deadline_after && deadline_after>0);

    cvlr_assert!(action == Action::CommitUpgrade);
}

/** 
 *  RULE: 
 *      Deadline changed to zero value => applyUpgrade or revertUpgrade was called 
 *  Passing test: https://prover.certora.com/output/7145022/4389bd079e294e6cb4afd7a4a025c8de/?anonymousKey=f9c41c589079e74f54a0fe42ef27cc7df6827145&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Atrue%2C%22fileViewCollapsed%22%3Afalse%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22file%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%22uiID%22%3A%225e0142%22%2C%22output%22%3A%22.certora_sources%2Ffees_collector%2Fsrc%2Fcertora_specs%2Ffee_collector_rules.rs%22%2C%22name%22%3A%22fee_collector_rules.rs%22%7D%2C%22fileViewFilter%22%3A%22fee%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%22677593%22%2C%22cc8692%22%2C%2292951d%22%2C%2217404f%22%2C%222f3e0b%22%2C%225c4625%22%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Validation test: https://prover.certora.com/output/7145022/b48256f2cfd24a24aa1d5cd6f540220f/?anonymousKey=ec154ff7d1ee78f91fdadc9b2de322c8d25a96c3&params=%7B%222%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%2212-10-1-1-1-1-1-010_12-1-1-1-1%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Atrue%2C%22fileViewCollapsed%22%3Afalse%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%22uiID%22%3A%225d9ea1%22%2C%22output%22%3A%22.certora_sources%2Ffees_collector%2Fsrc%2Fcertora_specs%2Ffee_collector_rules.rs%22%2C%22name%22%3A%22fee_collector_rules.rs%22%7D%2C%22fileViewFilter%22%3A%22fee%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A2%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%222-10-1-02-1-1-1-1-1-1-1-1%22%2C%22expandedFilesState%22%3A%5B%224d4d28%22%2C%2285fece%22%2C%22396952%22%2C%2236ce6c%22%2C%22d6ed68%22%2C%2268b424%22%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: No
 *  Note: validated by removing applyUpgrade
*/
#[rule]
pub fn deadline_changed_due_to_revert_or_apply_upgrade(e: Env){

    let deadline_before= get_upgrade_deadline(&e);

    //Execute Operation
    let action = nondet_func(e.clone());

    let deadline_after= get_upgrade_deadline(&e);

    // assume deadline changed to nonzero value
    cvlr_assume!(deadline_before != deadline_after && deadline_after==0);

    cvlr_assert!(action == Action::RevertUpgrade || action == Action::ApplyUpgrade);
}

/** 
 *  RULE: 
 *      Deadline changed => (from 0 => deadline>currenttimestamp)
 *                          (from deadline =! 0 => deadline = 0)   
 *  Passing test: https://prover.certora.com/output/7145022/4389bd079e294e6cb4afd7a4a025c8de/?anonymousKey=f9c41c589079e74f54a0fe42ef27cc7df6827145&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Atrue%2C%22fileViewCollapsed%22%3Afalse%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22file%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%22uiID%22%3A%225e0142%22%2C%22output%22%3A%22.certora_sources%2Ffees_collector%2Fsrc%2Fcertora_specs%2Ffee_collector_rules.rs%22%2C%22name%22%3A%22fee_collector_rules.rs%22%7D%2C%22fileViewFilter%22%3A%22fee%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%22677593%22%2C%22cc8692%22%2C%2292951d%22%2C%2217404f%22%2C%222f3e0b%22%2C%225c4625%22%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Validation test: https://prover.certora.com/output/7145022/b48256f2cfd24a24aa1d5cd6f540220f/?anonymousKey=ec154ff7d1ee78f91fdadc9b2de322c8d25a96c3&params=%7B%222%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%2212-10-1-1-1-1-1-010_12-1-1-1-1%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Atrue%2C%22fileViewCollapsed%22%3Afalse%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%22uiID%22%3A%225d9ea1%22%2C%22output%22%3A%22.certora_sources%2Ffees_collector%2Fsrc%2Fcertora_specs%2Ffee_collector_rules.rs%22%2C%22name%22%3A%22fee_collector_rules.rs%22%7D%2C%22fileViewFilter%22%3A%22fee%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A2%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%222-10-1-02-1-1-1-1-1-1-1-1%22%2C%22expandedFilesState%22%3A%5B%224d4d28%22%2C%2285fece%22%2C%22396952%22%2C%2236ce6c%22%2C%22d6ed68%22%2C%2268b424%22%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Bugs: No
 *  Note: validated by removing applyUpgrade
*/
#[rule]
pub fn deadline_state_transition_upgrade(e: Env){

    let deadline_before= get_upgrade_deadline(&e);

    //Execute Operation
    nondet_func(e.clone());

    let deadline_after= get_upgrade_deadline(&e);

    //assume deadline changed
    cvlr_assume!(deadline_before != deadline_after);

    if deadline_before==0{
        cvlr_assert!(deadline_after>e.ledger().timestamp());
    }
    else{
        cvlr_assert!(deadline_after == 0);
    }
}
/** 
 *  RULE: 
 *      Cannot commit if deadline > 0 
 *  Passed: https://prover.certora.com/output/7145022/2eb21896630b4aaba2ebab6938b5d984/?anonymousKey=2bc94456fd21b606f7aa7e0892810c1fd5243016&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Verified: https://prover.certora.com/output/7145022/7838738ab1cb45458b67b9116c8b6196/?anonymousKey=c6b4c0373d8e176ea868882a00496be4aa9cc746
 *  Bugs: No
 *  Note: Verified by assuming deadline >= 0 
*/
#[rule]
pub fn cant_commit_if_deadline_nonzero_upgrade(e: Env){
    
    let deadline:u64 = get_upgrade_deadline(&e);

    cvlr_assume!(deadline != 0);

    FeesCollector::commit_upgrade(e.clone(), nondet_address(), nondet_wasm());

    //cvlr_satisfy!(true);
    cvlr_assert!(false); // Should not reach -> should pass
}

/** 
 *  RULE: 
 *      Cannot apply if currenttime < deadline
 *  Passed: https://prover.certora.com/output/7145022/2eb21896630b4aaba2ebab6938b5d984/?anonymousKey=2bc94456fd21b606f7aa7e0892810c1fd5243016&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 *  Verified: https://prover.certora.com/output/7145022/7838738ab1cb45458b67b9116c8b6196/?anonymousKey=c6b4c0373d8e176ea868882a00496be4aa9cc746
 *  Bugs: No
 *  Note: Verified by assuming deadline >= 0 
*/
#[rule]
pub fn cant_apply_before_deadline_upgrade(e: Env){
    
    let deadline:u64 = get_upgrade_deadline(&e);

    cvlr_assume!(e.ledger().timestamp() < deadline);

    FeesCollector::commit_upgrade(e.clone(), nondet_address(), nondet_wasm());

    //cvlr_satisfy!(true);
    cvlr_assert!(false); // Should not reach -> should pass
}

/** 
 *  RULE: -- 
 *      future wasm changed => deadline changed
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn future_wasm_changed_deadline_changed(e: Env){

    let future_wasm_before = upgrade::storage::get_future_wasm(&e);
    let deadline_before = upgrade::storage::get_upgrade_deadline(&e);

    nondet_func(e.clone());

    let future_wasm_after = upgrade::storage::get_future_wasm(&e);
    let deadline_after = upgrade::storage::get_upgrade_deadline(&e);

    cvlr_assume!(future_wasm_before != future_wasm_after);

    cvlr_assert!(deadline_before != deadline_after);
}

/** 
 *  RULE: -- 
 *      future wasm cant become None
 *  Tested: No
 *  Bugs: No
 *  Note: 
 *       
*/
#[rule]
pub fn future_cant_be_none(e: Env){

    let future_wasm_before = upgrade::storage::get_future_wasm(&e);

    nondet_func(e.clone());

    let future_wasm_after = upgrade::storage::get_future_wasm(&e);

    cvlr_assume!(future_wasm_before != future_wasm_after);

    cvlr_assert!(future_wasm_after.is_some());
}



/*------------------------------------------------------------------------------------------ */
/**
 * UNIT TESTS
 */

/** 
 * Function: commit_transfer_ownership
 * 
 * Functinality
 *  - Only admin
 *  - Sets future wasm
 *  - Sets deadline
 * 
 * https://prover.certora.com/output/7145022/5f92ae1a4b8f403ea06a65c3c01678ca/?anonymousKey=133f486ffb954a83e8bc07768d52ec8704331af7&params=%7B%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3Anull%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */

#[rule]
pub fn commit_upgrade_integrity(e: Env){
    let admin = get_role_safe_address(Role::Admin);
    let new_wasm = nondet_wasm();

    FeesCollector::commit_upgrade(e.clone(), admin.clone().unwrap(), new_wasm.clone());

    let deadline = get_upgrade_deadline(&e);

    cvlr_assert!(   upgrade::storage::get_future_wasm(&e).unwrap() == new_wasm &&
                    deadline == e.ledger().timestamp() + 3 * 86400 &&
                    is_auth(admin.unwrap())) //storage::constants::UPGRADE_DELAY is private
    
}

/** 
 * Function: apply_upgrade
 * 
 * Functinality
 *  - Only admin
 *  - returns the new contract wasm == futureWasm
 *  - Sets deadline to 0
 * 
 * https://prover.certora.com/output/7145022/f2c21effbe9e4699828b3c644565b40e/?anonymousKey=288043d940c5f014faf51549bd4979e3fa39126d&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */

#[rule]
pub fn apply_upgrade_integrity(e: Env){
    let admin = get_role_safe_address(Role::Admin);
    let future_wasm = get_future_wasm(&e).unwrap();

    let new_wasm = FeesCollector::apply_upgrade(e.clone(), admin.clone().unwrap());

    let deadline = get_upgrade_deadline(&e);

    cvlr_assert!(   future_wasm == new_wasm &&
                    deadline == 0 &&
                    is_auth(admin.unwrap())) 
    
}

/** 
 * Function: revert_upgrade
 * 
 * Functinality
 *  - Only admin
 *  - Sets deadline to 0
 * 
 * https://prover.certora.com/output/7145022/6f59f450cae14b73bb2c73470738b8f1/?anonymousKey=6260df8aa028abb0f5e655ac987bc0f157309724&params=%7B%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3Anull%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */

#[rule]
pub fn revert_upgrade_integrity(e: Env){
    let admin = get_role_safe_address(Role::Admin);

    FeesCollector::apply_upgrade(e.clone(), admin.clone().unwrap());

    let deadline = get_upgrade_deadline(&e);

    cvlr_assert!(   deadline == 0 && is_auth(admin.unwrap())) 
    
}

/** 
 * Function: set_emergency_mode
 * 
 * Functinality
 *  - Only Emergency admin
 *  - Sets mode to bool value
 * 
 * https://prover.certora.com/output/7145022/3e5afc1498ba4b70817d5e96c7cd11f8/?anonymousKey=7ed4a64a573467a0123b0c0dbd749322a7bfd2e2&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */

#[rule]
pub fn set_emergency_mode_integrity(e: Env){
    let emergency_admin = get_role_safe_address(Role::EmergencyAdmin);
    let value: bool = nondet();

    FeesCollector::set_emergency_mode(e.clone(), emergency_admin.clone().unwrap(), value);

    cvlr_assert!( value == FeesCollector::get_emergency_mode(e.clone()) && is_auth(emergency_admin.unwrap())) 
    
}


/** 
 * Functin: commit_transfer_ownership
 * 
 * Functinality
 *  - Only admin
 *  - Sets future address
 *  - Sets deadline
 * https://prover.certora.com/output/7145022/24f5b7e0fc5d4d66afad6e1121023cac/?anonymousKey=eb6e272efca93bcb292ea3c5e3531a6006f31569&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22file%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 * 
 * Bugs: Doesnt work with Admin
 */
#[rule]
pub fn commit_transfer_ownership_integrity(e: Env){
    let admin = get_role_safe_address(Role::Admin);
    let role = nondet_role();
    //let role = Role::Admin;
    let future_add = nondet_address();

    FeesCollector::commit_transfer_ownership(e.clone(), admin.clone().unwrap(), role.clone().as_symbol(&e), future_add.clone());

    let deadline = get_transfer_deadline(&role);
    let future_add_after = FeesCollector::get_future_address(e.clone(), role.as_symbol(&e));
    clog!(cvlr_soroban::Addr(&future_add_after));

    cvlr_assert!(   future_add_after == future_add &&
                    deadline == e.ledger().timestamp() + access_control::constants::ADMIN_ACTIONS_DELAY &&
                    is_auth(admin.unwrap()));
    //cvlr_satisfy!(true);                
}

/** 
 * Functin: apply_transfer_ownership
 * 
 * Functinality
 *  - Only admin
 *  - Sets role to future address
 *  - Sets deadline == 0 
 * 
 * https://prover.certora.com/output/7145022/5219adadb51d4ceaa7844da5f1906039/?anonymousKey=c5f14aabcc99cdce026116024d3a519a26d45d04&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn apply_transfer_ownership_integrity(e: Env){
    let admin = get_role_safe_address(Role::Admin);
    let role = nondet_role();
    let future_add = FeesCollector::get_future_address(e.clone(), role.clone().as_symbol(&e));

    let deadline_before = get_transfer_deadline(&role);
    
    FeesCollector::apply_transfer_ownership(e.clone(), admin.clone().unwrap(), role.clone().as_symbol(&e));

    let deadline_after = get_transfer_deadline(&role);

    cvlr_assert!(   is_role(&future_add, &role)                 &&
                    deadline_before < e.ledger().timestamp()    &&
                    deadline_after == 0                         &&
                    is_auth(admin.unwrap()))
    
}

/** 
 * Function: revert_transfer_ownership
 * 
 * Functinality
 *  - Only admin
 *  - Sets deadline == 0 
 * 
 * https://prover.certora.com/output/7145022/bd4adbcd5d064757a3e001653ed70713/?anonymousKey=d30be73817f77f1efa1a5aa1996701c2fbc379d9&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn revert_transfer_ownership_integrity(e: Env){
    let admin = get_role_safe_address(Role::Admin);
    let role = nondet_role();

    FeesCollector::revert_transfer_ownership(e.clone(), admin.clone().unwrap(), role.clone().as_symbol(&e));

    let deadline = get_transfer_deadline(&role);

    cvlr_assert!( deadline == 0 && is_auth(admin.unwrap()));
    
}

/** 
 * Function: get_future_address for Admin role
 *              wrote the rule only for admin as proof of bug
 * 
 * Functinality
 *  - gets the future address
 * 
 * Bug: This rule is vacuos due to the From_symbol bug for admin.
 * Proof: https://prover.certora.com/output/7145022/a0a5735ee40e42d2bc60046fe64dc613/?anonymousKey=07b078fc93cd80fea26a2bbd9c816aa1ebf018ab&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Atrue%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn get_future_address_integrity_admin(e: Env){
    let role = Role::Admin;
    let access_control = AccessControl::new(&e);
    // Assume the future address is applicable
    //cvlr_assume!(get_transfer_deadline(&role)>0);
    //access_control.get_future_address(&role);
    let future_key = access_control.get_future_key(&role);
    let true_future_add: Address = e.storage().instance().get(&future_key).unwrap();

    let future_from_fees = FeesCollector::get_future_address(e.clone(), role.clone().as_symbol(&e));

    clog!(role.to_string());
    clog!(cvlr_soroban::Addr(&true_future_add));
    clog!(cvlr_soroban::Addr(&future_from_fees));

    //clog!(&access_control.get_transfer_ownership_deadline(&role));
    cvlr_satisfy!(true);
}

/** 
 * Function: get_future_address for nondet role
 * 
 * Functinality
 *  - gets the future address
 * https://prover.certora.com/output/7145022/db145f6e5ce54f89bedf76e84ae36080/?anonymousKey=fb450ad9ed27ad7498b5723591319a5fc0ae73ab&params=%7B%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3Anull%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn get_future_address_integrity_fees_collector(e: Env){
    let role = nondet_role();
    clog!(role.to_string());

    let access_control = AccessControl::new(&e);
    // Assume someone called commit
    cvlr_assume!(get_transfer_deadline(&role)>0);
    //access_control.get_future_address(&role);
    let future_key = access_control.get_future_key(&role);
    let true_future_add: Address = e.storage().instance().get(&future_key).unwrap();

    let future_from_fees = FeesCollector::get_future_address(e.clone(), role.clone().as_symbol(&e));

    clog!(cvlr_soroban::Addr(&true_future_add));
    clog!(cvlr_soroban::Addr(&future_from_fees));

    //clog!(&access_control.get_transfer_ownership_deadline(&role));
    cvlr_assert!(true_future_add == future_from_fees);
}

/** 
 * Function: get_emergency_mode
 * 
 * Functinality
 *  - gets the emergency mode
 * https://prover.certora.com/output/7145022/af20eb475f4048a9b21241215309a6bd/?anonymousKey=f1ff4a3b4fb78e9d356eed602b30b125d2457dde&params=%7B%221%22%3A%7B%22index%22%3A0%2C%22ruleCounterExamples%22%3A%5B%7B%22name%22%3A%22rule_output_1.json%22%2C%22selectedRepresentation%22%3A%7B%22label%22%3A%22PRETTY%22%2C%22value%22%3A0%7D%2C%22callResolutionSingleFilter%22%3A%22%22%2C%22variablesFilter%22%3A%22%22%2C%22callTraceFilter%22%3A%22%22%2C%22variablesOpenItems%22%3A%5Btrue%2Ctrue%5D%2C%22callTraceCollapsed%22%3Atrue%2C%22rightSidePanelCollapsed%22%3Afalse%2C%22rightSideTab%22%3A%22%22%2C%22callResolutionSingleCollapsed%22%3Atrue%2C%22viewStorage%22%3Atrue%2C%22variablesExpandedArray%22%3A%22%22%2C%22expandedArray%22%3A%22%22%2C%22orderVars%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22orderParams%22%3A%5B%22%22%2C%22%22%2C0%5D%2C%22scrollNode%22%3A0%2C%22currentPoint%22%3A0%2C%22trackingChildren%22%3A%5B%5D%2C%22trackingParents%22%3A%5B%5D%2C%22trackingOnly%22%3Afalse%2C%22highlightOnly%22%3Afalse%2C%22filterPosition%22%3A0%2C%22singleCallResolutionOpen%22%3A%5B%5D%2C%22snap_drop_1%22%3Anull%2C%22snap_drop_2%22%3Anull%2C%22snap_filter%22%3A%22%22%7D%5D%7D%7D&generalState=%7B%22fileViewOpen%22%3Afalse%2C%22fileViewCollapsed%22%3Atrue%2C%22mainTreeViewCollapsed%22%3Atrue%2C%22callTraceClosed%22%3Afalse%2C%22mainSideNavItem%22%3A%22rules%22%2C%22globalResSelected%22%3Afalse%2C%22isSideBarCollapsed%22%3Afalse%2C%22isRightSideBarCollapsed%22%3Atrue%2C%22selectedFile%22%3A%7B%7D%2C%22fileViewFilter%22%3A%22%22%2C%22mainTreeViewFilter%22%3A%22%22%2C%22contractsFilter%22%3A%22%22%2C%22globalCallResolutionFilter%22%3A%22%22%2C%22currentRuleUiId%22%3A1%2C%22counterExamplePos%22%3A1%2C%22expandedKeysState%22%3A%22%22%2C%22expandedFilesState%22%3A%5B%5D%2C%22outlinedfilterShared%22%3A%22000000000%22%7D
 */
#[rule]
pub fn get_emergency_mode_integrity(e: Env){
    
    let emergency_mode_key = access_control::storage::DataKey::EmergencyMode;
    let emergency_mode_from_fees = FeesCollector::get_emergency_mode(e.clone());
    let true_emergency_mode: bool = e.storage().instance().get(&emergency_mode_key).unwrap();

    cvlr_assert!(true_emergency_mode == emergency_mode_from_fees);

}