#![feature(generic_const_exprs)]

use ethers::providers::{Http, Provider};
use ethers::types::{H256, U256};
use ethers::utils::keccak256;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::CircuitFunction;
use plonky2x::utils::{address, bytes32};
use std::env;

use plonky2x::frontend::eth::vars::AddressVariable;
use plonky2x::frontend::vars::{Bytes32Variable, U32Variable, U256Variable, EvmVariable};
use plonky2x::prelude::{CircuitBuilder, BytesVariable};
use plonky2x::prelude::Variable;

pub struct U32AddFunction {}

fn slots_to_check_constant() {

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


        let block_hash = builder.constant::<Bytes32Variable>(bytes32!("0xb85ebe133832df0a4e0828f73c3536f9e6f7218966f9c7b965ed14f322fc4c29"));
        let swell_address = address!("0x46DdC39E780088B1B146Aba8cBBe15DC321A1A1d");
        let swell_address_variable = builder.constant::<AddressVariable>(swell_address);

        let four = builder.constant::<Bytes32Variable>(bytes32!("0x0000000000000000000000000000000000000000000000000000000000000004")); 
        let six = builder.constant::<Bytes32Variable>(bytes32!("0x0000000000000000000000000000000000000000000000000000000000000006")); 

        let result = builder.keccak256(&six.0.0); 
        builder.watch(&result, "1");
        let result_u256 = U256Variable::decode(&mut builder, &result.0.0);
        let one = builder.constant::<U256Variable>(U256::from(1));
        let result_plus_one = builder.add(result_u256, one);
        let bytes = result_plus_one.encode(&mut builder);
        let key = Bytes32Variable::decode(&mut builder, &bytes);
        builder.watch(&key, "input key");
        builder.watch(&swell_address_variable, "swell address");
        let value = builder.eth_get_storage_at(swell_address_variable, key, block_hash);
        builder.watch(&value, "value");
        let operator_id = builder.shr(value.0, 128);
        let mut key_index = builder.shl(value.0, 128); 
        key_index = builder.shr(key_index, 128); 

        builder.watch(&operator_id, "operator_id");
        builder.watch(&key_index, "key_index");

        let mut concatenated = builder.init::<BytesVariable<64>>();
        for i in 0..32 {
            concatenated.0[i] = operator_id.0[i];
            concatenated.0[32+i] = four.0.0[i];
        }
        let validator_position = builder.keccak256(&concatenated.0);
        let pubkey_position = builder.keccak256(&validator_position.0.0);
        let pubkey_position_u256 = U256Variable::decode(&mut builder, &pubkey_position.0.0);
        let key_u256 = U256Variable::decode(&mut builder, &key_index.0);
        let pubkey_position_plus_key_u256 = builder.add(pubkey_position_u256, key_u256);
        let bytes = pubkey_position_plus_key_u256.encode(&mut builder);
        let pubkey_position_plus_key = Bytes32Variable::decode(&mut builder, &bytes);
        let pubkey_bytes_position = builder.keccak256(&pubkey_position_plus_key.0.0);

        let pubkey_part_1 = builder.eth_get_storage_at(swell_address_variable, pubkey_bytes_position, block_hash);
        builder.watch(&pubkey_part_1, "to");

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
