// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/SwellProvider.sol";

contract SwellProviderScript is Script {
    function run() public {
        // Note: need to use recent block root at multiple of 32 minus 1 due to caching limits.
        vm.broadcast();
        SwellProvider s = SwellProvider(0xf772793d06C4461273BC02478f2Fd720FdBc5DD7);
        bytes32 blockRoot = 0x84301bd8b4bdc926d4f5610c3ee5e5224bd3306c4f64eb656fad50312ba4d45d;
        s.requestProof{value: 30 gwei * 1_000_000}(blockRoot);
    }
}
