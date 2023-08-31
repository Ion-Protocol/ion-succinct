#![feature(generic_const_exprs)]

use ethers::providers::{Http, Provider};
use ethers::types::{H256, U256};
use ethers::utils::keccak256;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::CircuitFunction;
use plonky2x::frontend::eth::beacon::vars::BeaconValidatorsVariable;
use plonky2x::utils::eth::beacon::BeaconClient;
use plonky2x::utils::{address, bytes32};
use std::env;

use plonky2x::frontend::eth::vars::{AddressVariable, BLSPubkeyVariable};
use plonky2x::frontend::vars::{Bytes32Variable, EvmVariable, U256Variable, U32Variable};
use plonky2x::prelude::{BytesVariable, CircuitBuilder};
use plonky2x::prelude::{CircuitVariable, Variable};

pub struct U32AddFunction {}

fn slots_to_check_constant() {}

fn get_swell_validator_pubkey<F: RichField + Extendable<D>, const D: usize>(
    mut builder: &mut CircuitBuilder<F, D>,
    i: usize,
) -> BLSPubkeyVariable {
    let block_hash = builder.constant::<Bytes32Variable>(bytes32!(
        "0xb85ebe133832df0a4e0828f73c3536f9e6f7218966f9c7b965ed14f322fc4c29"
    ));
    let swell_address = address!("0x46DdC39E780088B1B146Aba8cBBe15DC321A1A1d");
    let swell_address_variable = builder.constant::<AddressVariable>(swell_address);

    let four = builder.constant::<Bytes32Variable>(bytes32!(
        "0x0000000000000000000000000000000000000000000000000000000000000004"
    ));
    let six = builder.constant::<Bytes32Variable>(bytes32!(
        "0x0000000000000000000000000000000000000000000000000000000000000006"
    ));
    let ONE = builder.constant::<U256Variable>(U256::from(1)); // number 1

    let one = builder.constant::<U256Variable>(U256::from(i)); // offset

    let result = builder.keccak256(&six.0 .0);
    let result_u256 = U256Variable::decode(&mut builder, &result.0 .0);

    let result_plus_one = builder.add(result_u256, one);
    let bytes = result_plus_one.encode(&mut builder);
    let key = Bytes32Variable::decode(&mut builder, &bytes); // result_plus_one

    let value = builder.eth_get_storage_at(block_hash, swell_address_variable, key);
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

    let pubkey_position_u256 = U256Variable::decode(&mut builder, &pubkey_position.0 .0);
    let key_u256 = U256Variable::decode(&mut builder, &key_index.0);

    let pubkey_position_plus_key_u256 = builder.add(pubkey_position_u256, key_u256);

    // pubkey part 1
    let bytes = pubkey_position_plus_key_u256.encode(&mut builder);
    let pubkey_position_plus_key = Bytes32Variable::decode(&mut builder, &bytes);
    let pubkey_bytes_position = builder.keccak256(&pubkey_position_plus_key.0 .0); // final address

    let pubkey_part_1 =
        builder.eth_get_storage_at(block_hash, swell_address_variable, pubkey_bytes_position);

    // pubkey part 2 position = (pubkey_bytes_position + 1)
    let pubkey_bytes_position_u256 =
        U256Variable::decode(&mut builder, &pubkey_bytes_position.0 .0);

    let pubkey_bytes_position_plus_one = builder.add(pubkey_bytes_position_u256, ONE);
    let bytes = pubkey_bytes_position_plus_one.encode(&mut builder);
    let pubkey_bytes_position_part_two: Bytes32Variable =
        Bytes32Variable::decode(&mut builder, &bytes);
    let pubkey_part_2 = builder.eth_get_storage_at(
        block_hash,
        swell_address_variable,
        pubkey_bytes_position_part_two,
    );

    // combine part 1 and 2
    // part 2 = shift 2 to the left two chars, right (32 + 2) chars
    // part 1 || part 2
    // let pubkey_part_2_sliced: BytesVariable<16>;
    // pubkey_part_2_sliced = BytesVariable::<16>(pubkey_part_2.as_bytes()[..16]);

    let pubkey = builder.init::<BLSPubkeyVariable>();
    let mut pubkey_bytes = pubkey.0;

    for i in 0..32 {
        pubkey_bytes.0[i] = pubkey_part_1.0 .0[i];
    }

    for i in 0..16 {
        pubkey_bytes.0[i + 32] = pubkey_part_2.0 .0[i];
    }

    BLSPubkeyVariable(pubkey_bytes)

    // First BLS PUBKEY was set to [168, 151, 125, 39, 137, 252, 62, 100, 148, 43, 196, 0, 54, 20, 63, 54, 86, 126, 56, 28, 99, 236, 54, 66, 66, 59, 88, 140, 167, 222, 120, 30, 198, 2, 3, 254, 135, 187, 77, 159, 24, 20, 163, 89, 221, 242, 101, 221]
    //  final hex should be dd
    // Second BLS PUBKEY was set to [145, 133, 43, 78, 102, 242, 22, 109, 54, 79, 194, 137, 25, 169, 152, 91, 173, 12, 46, 245, 31, 107, 26, 197, 48, 183, 229, 26, 158, 68, 217, 65, 8, 85, 245, 1, 108, 75, 65, 102, 102, 108, 117, 240, 168, 11, 107, 124]
    //  final hex should be 7c
    // first key
    // true     0xa8977d2789fc3e64942bc40036143f36567e381c63ec3642423b588ca7de781ec60203fe87bb4d9f1814a359ddf265dd
    // combine  0xa8977d2789fc3e64942bc40036143f36567e381c63ec3642423b588ca7de781ec60203fe87bb4d9f1814a359ddf265dd00000000000000000000000000000000
    // second key
    // true     0x91852b4e66f2166d364fc28919a9985bad0c2ef51f6b1ac530b7e51a9e44d9410855f5016c4b4166666c75f0a80b6b7c
    // part one 0x91852b4e66f2166d364fc28919a9985bad0c2ef51f6b1ac530b7e51a9e44d941
    // part two 0x0855f5016c4b4166666c75f0a80b6b7c00000000000000000000000000000000
    // combine  0x91852b4e66f2166d364fc28919a9985bad0c2ef51f6b1ac530b7e51a9e44d9410855f5016c4b4166666c75f0a80b6b7c00000000000000000000000000000000
}

impl CircuitFunction for U32AddFunction {
    fn build<F, C, const D: usize>() -> Circuit<F, C, D>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let mut builder = CircuitBuilder::<F, D>::new();

        // bytes memory inputs = abi.encode(blockHash, beaconRoot);

        // are read in order for the events, shouold be Event(blockHash, beaconRoot)
        let beacon_root = builder.evm_read::<Bytes32Variable>(); // reads from the event that succinct indexes, just an additional input
        let beacon_hash = builder.evm_read::<Bytes32Variable>();

        let rpc_url = env::var("RPC_1").unwrap();
        let provider = Provider::<Http>::try_from(rpc_url).unwrap();
        builder.set_execution_client(provider);
        let beacon_url = env::var("CONSENSUS_RPC").unwrap();
        let client = BeaconClient::new(beacon_url);
        builder.set_beacon_client(client);

        let mut pubkeys: Vec<BLSPubkeyVariable> = Vec::new();
        for i in 0..5 {
            pubkeys.push(get_swell_validator_pubkey(&mut builder, i));
        }

        // hardcode validator index for the pubkeys (later add to generator)
        let validator_idxs = vec![
            builder.constant::<Variable>(F::from_canonical_u64(586163)),
            builder.constant::<Variable>(F::from_canonical_u64(588675)),
            builder.constant::<Variable>(F::from_canonical_u64(588676)),
            builder.constant::<Variable>(F::from_canonical_u64(593963)),
            builder.constant::<Variable>(F::from_canonical_u64(593964)),
        ];

        let validators = builder.get_beacon_validators(beacon_root);

        let mut balances: Vec<U256Variable> = Vec::new();
        for i in 0..5 {
            let bal = builder.get_beacon_validator_balance(validators, validator_idxs[i]);
            balances.push(bal);
        }

        let mut sum: U256Variable = builder.constant::<U256Variable>(U256::from(0));

        for bal in balances {
            sum = builder.add(sum, bal);
        }

        builder.evm_write(sum);
        builder.build::<C>()
    }
}

fn main() {
    env::set_var("RUST_LOG", "info");
    U32AddFunction::cli();
}

#[cfg(test)]
mod tests {
    use plonky2x::prelude::{GoldilocksField, PoseidonGoldilocksConfig};

    use super::*;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_circuit() {
        dotenv::dotenv().ok();
        env_logger::init();
        let circuit = U32AddFunction::build::<F, C, D>();
        let mut input = circuit.input();

        // Input Data
        // (block height 18030531)
        // beacon root 0x42d26f5f8aebe6e979f09810ebec207c439a16b37dbcf88420aefe581590df87
        // block hash 0x1ebf7efd8e0dec7358e713c5f528fa5d01734e00698d6094704b404774a28a67

        // write for the test to read from
        input.evm_write::<Bytes32Variable>(bytes32!(
            "0x42d26f5f8aebe6e979f09810ebec207c439a16b37dbcf88420aefe581590df87"
        )); // beacon root
        input.evm_write::<Bytes32Variable>(bytes32!(
            "0x1ebf7efd8e0dec7358e713c5f528fa5d01734e00698d6094704b404774a28a67"
        )); // beacon hash
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
        let sum = output.evm_read::<U256Variable>();
        println!("{}", sum);

        // 32.01220
    }

    // array
    // 0xa8977d2789fc3e64942bc40036143f36567e381c63ec3642423b588ca7de781ec60203fe87bb4d9f1814a359ddf265dd,
    // 0x91852b4e66f2166d364fc28919a9985bad0c2ef51f6b1ac530b7e51a9e44d9410855f5016c4b4166666c75f0a80b6b7c,
    // 0xaafad3356633608da47421121c4260b8138d206045de2caa597e82e7294b9093e0567d5816b70e1e4c5e5ae7e8b95333,
    // 0xb389c46605c71eafcd7791611458e7346fe6ddab4b9ae1d29ba647e4cc46771fb8892d9bdc900b3a80ed2c25b278aae5,
    // 0xb7d1cbd6927d856d7e34333a8fb05c942effe38a7b19cef4d65124065c4600f3b9546d1e3c5131e1976486554fdbacb8,

    // 32.01220
    // 32.01225
    // 32.01224
    // 32.01211
    // 32.01206

    // fn test_sum_circuit() {
    //     env_logger::init();
    //     let circuit = U32AddFunction::build::<F, C, D>();
    //     let input = circuit.input();
    //     input.evm_write()
    //     // circuit.verify(proof);
    // }
}
