// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

interface IFunctionGateway {
    function request(
        bytes32 functionId,
        bytes memory inputs,
        bytes4 callbackSelector,
        bytes memory context
    ) external payable;
}

contract IonOracleV1 {
    /// @notice The address of the wstETH token provided by Lido.
    address public constant LIDO_TOKEN_ADDRESS = 0xf951E335afb289353dc249e82926178EaC7DEd78;

    /// @notice The address of the swETH token provided by Swell.
    address public constant SWELL_TOKEN_ADDRESS = 0xf951E335afb289353dc249e82926178EaC7DEd78;

    /// @notice The address of the function gateway.
    address public constant FUNCTION_GATEWAY =
        0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8;

    /// @notice The function id of the consensus oracle.
    bytes32 public constant FUNCTION_ID =
        0xb5bada68511661ed17b3c90b877a3459c4f671fb32bd0abdc1853615f8d160d8;

    /// @notice The nonce of the oracle.
    uint256 public nonce = 0;

    /// @notice The total value locked for each provider, indexed by ERC20 address.
    mapping(address => uint64) public tvl;

    /// @dev The event emitted when a callback is received.
    event IonOracleV1Update(uint256 requestId, uint64 lido, uint64 swell);

    /// @dev A helper function to read a pair of uint64s from a bytes array.
    function readTwoUint64(bytes memory _output) internal pure returns (uint64, uint64) {
        uint64 value1;
        uint64 value2;
        assembly {
            value1 := mload(add(_output, 0x08))
            value2 := mload(add(_output, 0x10))
        }
        return (value1, value2);
    }

    /// @notice The entrypoint for requesting an oracle update.
    function requestUpdate(bytes32 blockRoot) external payable {
        IFunctionGateway(FUNCTION_GATEWAY).request{value: msg.value}(
            FUNCTION_ID,
            abi.encodePacked(blockRoot),
            this.handleUpdate.selector,
            abi.encode(nonce)
        );
        nonce++;
    }

    /// @notice The callback function for the oracle.
    function handleUpdate(
        bytes memory output,
        bytes memory context
    ) external {
        require(msg.sender == FUNCTION_GATEWAY);
        uint256 requestId = abi.decode(context, (uint256));
        (uint64 lido, uint64 swell) = readTwoUint64(output);
        tvl[LIDO_TOKEN_ADDRESS] = lido;
        tvl[SWELL_TOKEN_ADDRESS] = swell;
        emit IonOracleV1Update(requestId, lido, swell);
    }
}
