// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/IonOracleV1.sol";

contract RequestUpdateScript is Script {
    function run() public {
        vm.broadcast();
        IonOracleV1 s = IonOracleV1(0x0d7F5B7dD6569cBC991407151d7f091f6617f6d1);
        bytes32 blockRoot = 0x84301bd8b4bdc926d4f5610c3ee5e5224bd3306c4f64eb656fad50312ba4d45d;
        s.requestUpdate{value: 30 gwei * 1_000_000}(blockRoot);
    }
}
