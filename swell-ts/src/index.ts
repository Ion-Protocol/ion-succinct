import * as dotenv from "dotenv";
import { providers, ethers, BigNumber } from "ethers";

dotenv.config({ path: ".env" });

function storageKeyFromBigNum(x: BigNumber) {
  return "0x" + x.toHexString().slice(2).padStart(64, "0");
}

async function main() {
  let swellAddress = "0x46DdC39E780088B1B146Aba8cBBe15DC321A1A1d";
  const activeValidatorIndexesSlot = BigNumber.from(6); // uint256
  const activeValidatorIndexesKey = storageKeyFromBigNum( // bytes32
    activeValidatorIndexesSlot
  );
  let operatorIdToValidatorDetailsSlot = BigNumber.from(4); // uint256
  let operatorIdToValidatorDetailsKey = storageKeyFromBigNum( // bytes32
    operatorIdToValidatorDetailsSlot
  );
  let rpc = process.env.RPC_1;
  const provider = new providers.JsonRpcProvider(rpc);
  for (let i = 0; i < 50; i++) {
    let activeValidatorIndexesPosition = BigNumber.from(
      ethers.utils.keccak256(activeValidatorIndexesKey)
    ).add(BigNumber.from(i));
    console.log(activeValidatorIndexesPosition);
    let value = BigNumber.from(
      await provider.getStorageAt(swellAddress, activeValidatorIndexesPosition)
    );

    let operatorId = value.shr(128);
    let keyIndex = value.and(BigNumber.from(1).shl(128).sub(1));

    let validatorDetailsPosition = BigNumber.from(
      ethers.utils.keccak256(
        storageKeyFromBigNum(operatorId).concat(
          operatorIdToValidatorDetailsKey.slice(2)
        )
      )
    );
    let pubkeyPosition = BigNumber.from(
      ethers.utils.keccak256(storageKeyFromBigNum(validatorDetailsPosition))
    ).add(keyIndex);

    let pubkeyBytesPosition = ethers.utils.keccak256(
      storageKeyFromBigNum(pubkeyPosition)
    );
    let pubkeyPart1 = await provider.getStorageAt(
      swellAddress,
      pubkeyBytesPosition
    );
    let pubkeyPart2 = await provider.getStorageAt(
      swellAddress,
      BigNumber.from(pubkeyBytesPosition).add(1).toHexString()
    );
    console.log("Iteration 1");
    console.log("> Operation ID:", operatorId.toHexString());
    console.log("> Key Index:", keyIndex.toHexString());
    console.log("> Pubkey:", (pubkeyPart1 + pubkeyPart2).slice(0, 98));

  }
}

main().catch(console.error);
