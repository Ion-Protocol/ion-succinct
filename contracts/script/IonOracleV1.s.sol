// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import "../src/IonOracleV1.sol";

contract RequestUpdateScript is Script {
    function run() public {
        vm.broadcast();
        IonOracleV1 s = IonOracleV1(0xc63b1AEc9CC21601c208d520C93DC0423E60747F);
        bytes32 blockRoot = 0x4f1dd351f11a8350212b534b3fca619a2a95ad8d9c16129201be4a6d73698adb;
        s.requestUpdate{value: 30 gwei * 1_000_000}(blockRoot);
    }
}
