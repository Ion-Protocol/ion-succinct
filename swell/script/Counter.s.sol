// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import {NodeOperatorRegistry} from "src/download/NodeOperatorRegistry.sol"; 


contract CounterScript is Script {
    function setUp() public {}


    function getDataAtSlot(uint256 slot) public view returns (uint256) {
        uint256 result;
        assembly {
            result := sload(slot)
        }
        return result;
    }

    function run() public {
        vm.broadcast();

        uint256 activeValidatorIndexesSlot = 6; 
        uint256 operatorIdToValidatorDetailsSlot = 4; 

        for (uint i = 0; i < 1400; i++) {
            bytes32 valuesSlot = bytes32(uint256(keccak256(abi.encodePacked(bytes32(activeValidatorIndexesSlot)))) + i);
            uint256 values = getDataAtSlot(uint256(valuesSlot));

            uint128 operatorId = uint128(values >> 128);
            uint128 keyIndex = uint128(values);

            bytes32 validatorDetailsSetSlot = bytes32(uint256(keccak256(abi.encodePacked(bytes32(operatorIdToValidatorDetailsSlot)))) + operatorId);
            bytes32 pubKeyIndexSlot = bytes32(uint256(keccak256(abi.encodePacked(validatorDetailsSetSlot))) + keyIndex);

            bytes32 pubkey = bytes32(getDataAtSlot(uint256(pubKeyIndexSlot))); 
            console.logBytes32(pubkey); 
        }
    }
}
