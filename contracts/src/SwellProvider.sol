// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

interface IFunctionGateway {
    function request(
        bytes32 functionId,
        bytes memory inputs,
        bytes4 select,
        bytes memory context
    ) external payable;
}

contract SwellProvider {
    uint256 public nextRequestId = 1;
    address public constant FUNCTION_GATEWAY =
        0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8;
    bytes32 public constant FUNCTION_ID =
        0x029711e1f436752cef2871b01728fada9b2ae189a50c280baee6732ae6c69ab8;

    event CallbackReceived(uint256 requestId, uint64 result);

    function readUint64(bytes memory _output) internal pure returns (uint64) {
        uint64 value;
        assembly {
            value := mload(add(_output, 0x08))
        }
        return value;
    }

    #[zk]
    function compute(bytes32 a, bytes32 b) returns (u64) {
        // todod
        return 0;
    }

    function requestProof(bytes32 blockRoot) external payable {
        bytes32 blockHash = 0xbf55aabec79b2720fde32b5878bdc580b15289d74105eb09a509a3d32ce54664;
        IFunctionGateway(FUNCTION_GATEWAY).request{value: msg.value}(
            FUNCTION_ID,
            abi.encodePacked(blockRoot, blockHash),
            this.handleCallback.selector,
            abi.encode(nextRequestId)
        );
        nextRequestId++;
    }

    function handleCallback(
        bytes memory output,
        bytes memory context
    ) external {
        require(msg.sender == FUNCTION_GATEWAY);
        uint256 requestId = abi.decode(context, (uint256));
        uint64 result = readUint64(output);
        emit CallbackReceived(requestId, result);
    }
}
