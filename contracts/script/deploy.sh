source ../.env
forge create src/IonOracleV1.sol:IonOracleV1 \
    --rpc-url $RPC_5 \
    --private-key $PRIVATE_KEY \
    --verify \
    --etherscan-api-key $ETHERSCAN_API_5