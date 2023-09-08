// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/SwellProvider.sol";

contract SwellProviderScript is Script {
    function run() public {
        // Note: need to use recent block root due to caching limits.
        vm.broadcast();
        SwellProvider s = SwellProvider(0xf772793d06C4461273BC02478f2Fd720FdBc5DD7);
        bytes32 blockRoot = 0x2e97f0f79b56670840c77972699b493fd2d748ab3c164e8e48b9b891c9a0c246;
        s.requestProof{value: 30 gwei * 1_000_000}(blockRoot);
    }
}
