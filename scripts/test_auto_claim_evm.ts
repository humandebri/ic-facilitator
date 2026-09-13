// Local-only contract integration probe. Runtime is supplied as a file so this
// script cannot accidentally send a transaction to the source network.
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createPublicClient, createTestClient, createWalletClient, http, parseAbi, toHex, keccak256, type Hex, type Abi } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { BATCH_SETTLEMENT_ADDRESS, BATCH_SETTLEMENT_DOMAIN, voucherTypes, claimBatchTypes } from "@x402/evm";

const url = "http://127.0.0.1:18548";
const publicClient = createPublicClient({ chain: foundry, transport: http(url) });
assert.equal(await publicClient.getChainId(), 31337);
const test = createTestClient({ chain: foundry, mode: "anvil", transport: http(url) });
const payer = privateKeyToAccount(toHex(1n, { size: 32 }));
const receiver = privateKeyToAccount(toHex(2n, { size: 32 }));
const wallet = createWalletClient({ chain: foundry, account: payer, transport: http(url) });
await test.setBalance({ address: payer.address, value: 10n ** 20n });
const runtime = readFileSync(process.env.BATCH_RUNTIME_PATH ?? "/tmp/ic-auto-claim-runtime.hex", "utf8").trim() as Hex;
assert.match(runtime, /^0x[0-9a-f]+$/i);
await test.setCode({ address: BATCH_SETTLEMENT_ADDRESS, bytecode: runtime });
const configType = "(address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt)";
const abi = parseAbi([
  `function deposit(${configType} config,uint128 amount,address collector,bytes data)`,
  `function getChannelId(${configType} config) view returns (bytes32)`,
  `function initiateWithdraw(${configType} config,uint128 amount)`,
  `function finalizeWithdraw(${configType} config)`,
  `function claimWithSignature(((${configType} channel,uint128 maxClaimableAmount) voucher,bytes signature,uint128 totalClaimed)[] claims,bytes signature)`,
  "function channels(bytes32 id) view returns (uint128 balance,uint128 totalClaimed)",
  "function pendingWithdrawals(bytes32 id) view returns (uint128 amount,uint40 initiatedAt)"
]);
async function deploy(name: string, args: readonly unknown[] = []) {
  const artifact = JSON.parse(readFileSync(`test/amoy/out/TestDepositToken.sol/${name}.json`, "utf8")) as {abi: Abi; bytecode: {object: Hex}};
  const hash = await wallet.deployContract({ abi: artifact.abi, bytecode: artifact.bytecode.object, args });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  assert.equal(receipt.status, "success");
  assert.ok(receipt.contractAddress);
  return receipt.contractAddress;
}
const token = await deploy("TestDepositToken");
const collector = await deploy("FixedAmountDepositCollector", [token, 1000n]);
const mint = await wallet.writeContract({ address: token, abi: parseAbi(["function mint(address to,uint256 amount)"]), functionName: "mint", args: [collector, 2000n] });
await publicClient.waitForTransactionReceipt({ hash: mint });
const domain = { ...BATCH_SETTLEMENT_DOMAIN, chainId:31337, verifyingContract:BATCH_SETTLEMENT_ADDRESS };
const receipts: Record<string, string> = {};
for (const timely of [true, false]) {
  const channel = { payer:payer.address, payerAuthorizer:payer.address, receiver:receiver.address, receiverAuthorizer:receiver.address, token, withdrawDelay:900, salt:toHex(timely ? 1n : 2n, {size:32}) };
  const id = await publicClient.readContract({address:BATCH_SETTLEMENT_ADDRESS,abi,functionName:"getChannelId",args:[channel]}) as Hex;
  const send = async (functionName: string, args: readonly unknown[]) => {
    const hash = await wallet.writeContract({address:BATCH_SETTLEMENT_ADDRESS,abi: abi as Abi,functionName,args,gas:500000n});
    return publicClient.waitForTransactionReceipt({hash});
  };
  assert.equal((await send("deposit",[channel,1000n,collector,"0x"])).status,"success");
  // A signature may allow 200, but only the 100 actually consumed is claimed.
  const signature = await payer.signTypedData({domain,types:voucherTypes,primaryType:"Voucher",message:{channelId:id,maxClaimableAmount:200n}});
  const claims = [{voucher:{channel,maxClaimableAmount:200n},signature,totalClaimed:100n}];
  const authorizer = await receiver.signTypedData({domain,types:claimBatchTypes,primaryType:"ClaimBatch",message:{claims:[{channelId:id,maxClaimableAmount:200n,totalClaimed:100n}]}});
  assert.equal((await send("initiateWithdraw",[channel,1000n])).status,"success");
  const withdrawal = await publicClient.readContract({address:BATCH_SETTLEMENT_ADDRESS,abi,functionName:"pendingWithdrawals",args:[id]}) as readonly [bigint,number];
  assert.ok(withdrawal[1] > 0);
  if (timely) {
    const claim = await send("claimWithSignature",[claims,authorizer]);
    assert.equal(claim.status,"success"); receipts.timelyClaimGas = claim.gasUsed.toString();
    assert.equal((await send("claimWithSignature",[claims,authorizer])).status,"success");
  }
  await test.increaseTime({seconds:901}); await test.mine({blocks:1});
  assert.equal((await send("finalizeWithdraw",[channel])).status,"success");
  const state = await publicClient.readContract({address:BATCH_SETTLEMENT_ADDRESS,abi,functionName:"channels",args:[id]});
  assert.deepEqual(state,timely ? [100n,100n] : [0n,0n]);
  if (!timely) assert.equal((await send("claimWithSignature",[claims,authorizer])).status,"reverted");
}
console.log(JSON.stringify({network:"local-anvil",chainId:31337,runtimeHash:keccak256(runtime),tests:["claim only charged amount","same claim replay is idempotent","claim before withdrawal deadline preserves funds","claim after withdrawal fails"],...receipts},null,2));
