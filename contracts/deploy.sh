source ../.env
forge create src/SwellProvider.sol:SwellProvider \
    --rpc-url $RPC_5 \
    --private-key $PRIVATE_KEY \
    --verify \
    --etherscan-api-key $ETHERSCAN_API_KEY_5