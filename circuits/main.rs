//! A simple example of how to use plonky2x to do provider proofs.

use ethers::providers::{Http, Provider};
use ethers::types::U256;
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::config::PlonkParameters;
use plonky2x::backend::function::CircuitFunction;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::utils::eth::beacon::BeaconClient;
use plonky2x::utils::{address, bytes32};
use std::env;

use plonky2x::frontend::eth::vars::{AddressVariable, BLSPubkeyVariable};
use plonky2x::frontend::vars::{Bytes32Variable, EvmVariable, U256Variable};
use plonky2x::prelude::{BytesVariable, CircuitBuilder};

/// The address of the Swell Contract.
const SWELL_CONTRACT_ADDRESS: &str = "0x46DdC39E780088B1B146Aba8cBBe15DC321A1A1d";

/// The number 4 as a bytes32.
const FOUR_BYTES32: &str = "0x0000000000000000000000000000000000000000000000000000000000000004";

/// The number 6 as a bytes32.
const SIX_BYTES32: &str = "0x0000000000000000000000000000000000000000000000000000000000000006";

/// A circuit that computes the total value locked inside the Swell Contract.
pub struct SwellProviderCircuit {}

/// Gets the i'th validator public key stored in the Swell Contract.
fn get_swell_validator_pubkey<L: PlonkParameters<D>, const D: usize>(
    builder: &mut CircuitBuilder<L, D>,
    block_hash: Bytes32Variable,
    i: usize,
) -> BLSPubkeyVariable {
    // Setup constants.
    let swell_address = builder.constant::<AddressVariable>(address!(SWELL_CONTRACT_ADDRESS));
    let offset = builder.constant::<U256Variable>(U256::from(i));
    let one = builder.constant::<U256Variable>(U256::from(1));
    let four = builder.constant::<Bytes32Variable>(bytes32!(FOUR_BYTES32));
    let six = builder.constant::<Bytes32Variable>(bytes32!(SIX_BYTES32));

    let result = builder.keccak256(&six.as_bytes()).as_u256(builder);
    let result_plus_one = builder.add(result, offset).encode(builder);
    let key = Bytes32Variable::decode(builder, &result_plus_one);

    let value = builder.eth_get_storage_at(block_hash, swell_address, key);
    let operator_id = builder.shr(value.0, 128);
    let mut key_index = builder.shl(value.0, 128);
    key_index = builder.shr(key_index, 128);

    let mut concatenated = builder.init::<BytesVariable<64>>();
    for i in 0..32 {
        concatenated.0[i] = operator_id.0[i];
        concatenated.0[32 + i] = four.0 .0[i];
    }

    let validator_position = builder.keccak256(&concatenated.0);
    let pubkey_position = builder.keccak256(&validator_position.0 .0);

    let pubkey_position_u256 = U256Variable::decode(builder, &pubkey_position.0 .0);
    let key_u256 = U256Variable::decode(builder, &key_index.0);

    let pubkey_position_plus_key_u256 = builder.add(pubkey_position_u256, key_u256);

    // Note: pubkey part 1.
    let bytes = pubkey_position_plus_key_u256.encode(builder);
    let pubkey_position_plus_key = Bytes32Variable::decode(builder, &bytes);
    let pubkey_bytes_position = builder.keccak256(&pubkey_position_plus_key.0 .0);

    let pubkey_part_1 =
        builder.eth_get_storage_at(block_hash, swell_address, pubkey_bytes_position);

    // Note: pubkey part 2 position = (pubkey_bytes_position + 1).
    let pubkey_bytes_position_u256 = U256Variable::decode(builder, &pubkey_bytes_position.0 .0);

    let pubkey_bytes_position_plus_one = builder.add(pubkey_bytes_position_u256, one);
    let bytes = pubkey_bytes_position_plus_one.encode(builder);
    let pubkey_bytes_position_part_two: Bytes32Variable = Bytes32Variable::decode(builder, &bytes);
    let pubkey_part_2 =
        builder.eth_get_storage_at(block_hash, swell_address, pubkey_bytes_position_part_two);

    // Note: we need combine part 1 and 2.
    // > part 2 = shift 2 to the left two chars, right (32 + 2) chars
    // > part 1 || part 2
    let pubkey = builder.init::<BLSPubkeyVariable>();
    let mut pubkey_bytes = pubkey.0;
    for i in 0..32 {
        pubkey_bytes.0[i] = pubkey_part_1.0 .0[i];
    }
    for i in 0..16 {
        pubkey_bytes.0[i + 32] = pubkey_part_2.0 .0[i];
    }

    BLSPubkeyVariable(pubkey_bytes)
}

impl CircuitFunction for SwellProviderCircuit {
    fn build<L: PlonkParameters<D>, const D: usize>() -> Circuit<L, D> {
        // Initialize the builder.
        let mut builder = CircuitBuilder::<L, D>::new();

        // Add the execution client.
        let execution_rpc_url = env::var("RPC_1").unwrap();
        let provider = Provider::<Http>::try_from(execution_rpc_url).unwrap();
        builder.set_execution_client(provider);

        // Add the beacon client.
        let consensus_rpc_url = env::var("CONSENSUS_RPC_1").unwrap();
        let client = BeaconClient::new(consensus_rpc_url);
        builder.set_beacon_client(client);

        // Reads the following inputs from the emitted event on the EVM.
        let beacon_root = builder.evm_read::<Bytes32Variable>();
        let block_hash = builder.evm_read::<Bytes32Variable>();

        // Grab the first five swell validator pubkeys.
        let mut pubkeys: Vec<BLSPubkeyVariable> = Vec::new();
        for i in 0..5 {
            pubkeys.push(get_swell_validator_pubkey(&mut builder, block_hash, i));
        }

        let validators = builder.beacon_get_validators(beacon_root);
        let mut validator_idxs = Vec::new();
        for pubkey in pubkeys {
            let (validator_idx, _) = builder.beacon_get_validator_by_pubkey(validators, pubkey);
            validator_idxs.push(validator_idx);
        }

        // Grab the balances of the first five validators.
        let balances = builder.beacon_get_balances(beacon_root);
        let mut balances_u64: Vec<U64Variable> = Vec::new();
        for validator_idx in validator_idxs {
            let bal = builder.beacon_get_balance(balances, validator_idx);
            balances_u64.push(bal);
        }

        // Sum the balances.
        let mut sum: U64Variable = builder.constant::<U64Variable>(0.into());
        for bal in balances_u64 {
            sum = builder.add(sum, bal);
        }

        // Write the sum to the EVM.
        builder.evm_write(sum);

        builder.build()
    }
}

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();
    SwellProviderCircuit::cli();
}

#[cfg(test)]
mod tests {
    use plonky2x::backend::config::DefaultParameters;

    use super::*;

    type L = DefaultParameters;
    const D: usize = 2;

    #[test]
    fn test_circuit() {
        // Initialize the .env and enviroment logger. Run the test with RUST_LOG=debug to see
        // the debug logs.
        dotenv::dotenv().ok();
        env_logger::init();

        let consensus_rpc_url = env::var("CONSENSUS_RPC_1").unwrap();
        let beacon = BeaconClient::new(consensus_rpc_url);
        let block_root = beacon.get_finalized_block_root_sync().unwrap();

        // Build the circuit.
        let circuit = SwellProviderCircuit::build::<L, D>();

        // Initialize a new input stream. Write the beacon root and then the block hash.
        let mut input = circuit.input();
        input.evm_write::<Bytes32Variable>(bytes32!(block_root));
        input.evm_write::<Bytes32Variable>(bytes32!(
            "0xf60eff24c751fd2374430f9adb38cabf28218e7a9fe303218489fe56cc87d5e1"
        ));

        // Prove and verify the circuit.
        let (proof, mut output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        // Read the sum from the output stream.
        let sum = output.evm_read::<U64Variable>();
        println!("{}", sum);

        // Test the default serializers.
        circuit.test_default_serializers();
    }
}
