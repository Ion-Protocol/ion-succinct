// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/SwellProvider.sol";

contract SwellProviderScript is Script {
    function run() public {
        vm.broadcast();
        SwellProvider s = SwellProvider(0x8Dd1cDd8Ca34e0BB3F48Ff48998AAD6309e9Ffdb);
        bytes32 blockRoot = 0xfa4e59e6c3597325e01fdb62835e3cbb327784f3f8037be4c7b9005121e3dcdd;
        s.requestProof{value: 30 gwei * 1_000_000}(blockRoot);
    }
}
