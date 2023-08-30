#![feature(generic_const_exprs)]

use ethers::providers::{Http, Provider};
use ethers::types::{H256, U256};
use ethers::utils::keccak256;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::CircuitFunction;
use plonky2x::frontend::eth::beacon::vars::BeaconValidatorsVariable;
use plonky2x::utils::{address, bytes32};
use std::env;

use plonky2x::frontend::eth::vars::AddressVariable;
use plonky2x::frontend::vars::{Bytes32Variable, EvmVariable, U256Variable, U32Variable};
use plonky2x::prelude::Variable;
use plonky2x::prelude::{BytesVariable, CircuitBuilder};

pub struct U32AddFunction {}

fn slots_to_check_constant() {}

fn get_swell_validator_pubkey<F: RichField + Extendable<D>, const D: usize>(
    mut builder: &mut CircuitBuilder<F, D>,
    i: usize,
) {
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

    let value = builder.eth_get_storage_at(swell_address_variable, key, block_hash);
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
    builder.watch(&pubkey_bytes_position, "public key part one position"); 

    let pubkey_part_1 =
    builder.eth_get_storage_at(swell_address_variable, pubkey_bytes_position, block_hash);
    builder.watch(&pubkey_part_1, "public key part one");
    
    // pubkey part 2 position = (pubkey_bytes_position + 1)
    let pubkey_bytes_position_u256 = U256Variable::decode(&mut builder, &pubkey_bytes_position.0.0); 
    // builder.watch(&pubkey_bytes_position.0.0, "pubkey_bytes_position.0.0"); 

    let pubkey_bytes_position_plus_one = builder.add(pubkey_bytes_position_u256, ONE); 
    let bytes = pubkey_bytes_position_plus_one.encode(&mut builder); 
    let pubkey_bytes_position_part_two: Bytes32Variable = Bytes32Variable::decode(&mut builder, &bytes); 
    let pubkey_part_2 = builder.eth_get_storage_at(swell_address_variable, pubkey_bytes_position_part_two, block_hash); 
    
    builder.watch(&pubkey_bytes_position_u256, "PART 2 pubkey_bytes_position_u256"); 
    builder.watch(&pubkey_bytes_position_plus_one, "PART 2 pubkey_bytes_position_plus_one"); 
    // builder.watch(&bytes, "PART 2 pubkey_bytes_position_plus_one vector");
    builder.watch(&pubkey_bytes_position_part_two, "PART 2 public key part two position"); 
    builder.watch(&pubkey_part_2, "PART 2 public key part two");  

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

        let rpc_url = env::var("RPC_1").unwrap();
        let provider = Provider::<Http>::try_from(rpc_url).unwrap();
        builder.set_execution_client(provider);

        for i in 0..2 {
            get_swell_validator_pubkey(&mut builder, i);
            // hardcode the indexes 
        }

        // builder.get_beacon_validator_from_u64(validators, index);
        // let validator = BeaconValidatorsVariable::CircuitVariable::new();
        // builder.get_beacon_validator_from_u64(pubkey_part_1, index)

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
        env_logger::init();
        let circuit = U32AddFunction::build::<F, C, D>();
        let input = circuit.input();
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
    }
}
