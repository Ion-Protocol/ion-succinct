// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import "../src/IonOracleV1.sol";

contract RequestUpdateScript is Script {
    function run() public {
        vm.broadcast();
        IonOracleV1 s = IonOracleV1(0x7F53ffECA14F03Eb85038bE1720556A3F2Ee5966);
        bytes32 blockRoot = 0x4f1dd351f11a8350212b534b3fca619a2a95ad8d9c16129201be4a6d73698adb;
        s.requestUpdate{value: 30 gwei * 1_000_000}(blockRoot);
    }
}
