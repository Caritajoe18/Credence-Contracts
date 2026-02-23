#![cfg(test)]

use crate::*;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Env, Address};

// ============================================================================
// i128 OVERFLOW TESTS
// ============================================================================

#[test]
fn test_i128_bond_amount_at_max() {
    let e = Env::default();
    e.mock_all_auths();
    let contract_id = e.register_contract(None, CredenceBond);
    let client = CredenceBondClient::new(&e, &contract_id);

    let admin = Address::generate(&e);
    client.initialize(&admin);

    let identity = Address::generate(&e);
    // FIX: create_bond takes 3 arguments: identity, amount, duration
    let bond = client.create_bond(&identity, &i128::MAX, &86400_u64);

    assert_eq!(bond.bonded_amount, i128::MAX);
    assert!(bond.active);
}

#[test]
#[should_panic(expected = "top-up caused overflow")]
fn test_i128_overflow_on_top_up() {
    let e = Env::default();
    e.mock_all_auths();
    let contract_id = e.register_contract(None, CredenceBond);
    let client = CredenceBondClient::new(&e, &contract_id);

    let admin = Address::generate(&e);
    client.initialize(&admin);

    let identity = Address::generate(&e);
    client.create_bond(&identity, &(i128::MAX - 1000), &86400_u64);

    // FIX: Passes value instead of reference
    client.top_up(&2000); 
}

#[test]
#[should_panic(expected = "slashing caused overflow")]
fn test_i128_overflow_on_massive_slashing() {
    let e = Env::default();
    e.mock_all_auths();
    let contract_id = e.register_contract(None, CredenceBond);
    let client = CredenceBondClient::new(&e, &contract_id);

    let admin = Address::generate(&e);
    client.initialize(&admin);

    let identity = Address::generate(&e);
    client.create_bond(&identity, &(i128::MAX / 2), &86400_u64);

    client.slash( &(i128::MAX / 2));
    
    // Attempt to slash more, causing overflow in the slashed_amount tracker
    client.slash( &(i128::MAX / 2 + 2));
}

// ============================================================================
// u64 TIMESTAMP OVERFLOW TESTS
// ============================================================================

#[test]
#[should_panic(expected = "bond end timestamp would overflow")]
fn test_u64_overflow_on_end_timestamp() {
    let e = Env::default();
    e.mock_all_auths();
    
    // Set current timestamp to near max
    e.ledger().with_mut(|li| {
        li.timestamp = u64::MAX - 1000;
    });

    let contract_id = e.register_contract(None, CredenceBond);
    let client = CredenceBondClient::new(&e, &contract_id);

    let admin = Address::generate(&e);
    client.initialize(&admin);

    let identity = Address::generate(&e);
    // This should panic inside the contract if you have: bond_start.checked_add(duration)
    client.create_bond(&identity, &1000, &2000);
}

// ============================================================================
// SLASHING & WITHDRAWAL LOGIC
// ============================================================================

#[test]
fn test_slashing_exceeds_bonded_amount() {
    let e = Env::default();
    e.mock_all_auths();
    let contract_id = e.register_contract(None, CredenceBond);
    let client = CredenceBondClient::new(&e, &contract_id);

    let admin = Address::generate(&e);
    client.initialize(&admin);

    let identity = Address::generate(&e);
    client.create_bond(&identity, &1000, &86400_u64);

    // If your slash function caps at bonded_amount:
    let bond = client.slash( &2000);
    assert_eq!(bond.slashed_amount, 1000); 
}