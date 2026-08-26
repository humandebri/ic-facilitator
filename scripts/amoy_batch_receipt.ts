// scripts/amoy_batch_receipt.ts: Amoy上で100件batch claimを成功させ、receiptサイズを実測する。
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  getAddress,
  getContractAddress,
  hashTypedData,
  http,
  parseAbi,
  publicActions,
  toHex,
  zeroAddress
} from "viem";
import type { Address, Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { polygonAmoy } from "viem/chains";

import { loadDotenv } from "./env_file";

const DEFAULT_RPC_URL = "https://polygon-amoy.drpc.org";
const BATCH_ADDRESS = getAddress("0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003");
const ENV_PATH = resolve(process.cwd(), ".env.amoy.local");
const CLAIMS = 100;
const DEPOSIT_CHUNK = 20;
const REVERT_PROBE_GAS = 1_100_000n;
const STATE_PATH = resolve(process.cwd(), ".amoy/amoy-state.json");

const batchAbi = parseAbi([
  "function deposit((address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt) config,uint128 amount,address collector,bytes collectorData)",
  "function multicall(bytes[] data) returns (bytes[] results)",
  "function claimWithSignature((((address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt) channel,uint128 maxClaimableAmount) voucher,bytes signature,uint128 totalClaimed)[] voucherClaims,bytes authorizerSignature)",
  "function channels(bytes32 channelId) view returns (uint128 balance,uint128 totalClaimed)"
]);
const tokenAbi = parseAbi([
  "constructor()",
  "function mint(address to,uint256 amount)",
  "function balanceOf(address account) view returns (uint256)"
]);
const collectorAbi = parseAbi(["constructor(address token,uint256 amount)"]);
const channelTypes = {
  ChannelConfig: [
    { name: "payer", type: "address" },
    { name: "payerAuthorizer", type: "address" },
    { name: "receiver", type: "address" },
    { name: "receiverAuthorizer", type: "address" },
    { name: "token", type: "address" },
    { name: "withdrawDelay", type: "uint40" },
    { name: "salt", type: "bytes32" }
  ]
} as const;
const voucherTypes = {
  Voucher: [
    { name: "channelId", type: "bytes32" },
    { name: "maxClaimableAmount", type: "uint128" }
  ]
} as const;
const claimBatchTypes = {
  ClaimBatch: [{ name: "claims", type: "ClaimEntry[]" }],
  ClaimEntry: [
    { name: "channelId", type: "bytes32" },
    { name: "maxClaimableAmount", type: "uint128" },
    { name: "totalClaimed", type: "uint128" }
  ]
} as const;

type Artifact = { abi: unknown[]; bytecode: { object: Hex } };
type Channel = {
  payer: Address;
  payerAuthorizer: Address;
  receiver: Address;
  receiverAuthorizer: Address;
  token: Address;
  withdrawDelay: number;
  salt: Hex;
};
type AmoyState = { collector?: Address; token?: Address };

function readState(): AmoyState {
  return existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) as AmoyState : {};
}

function writeState(state: AmoyState): void {
  mkdirSync(dirname(STATE_PATH), { recursive: true });
  writeFileSync(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`);
}

function initEnv(): void {
  if (existsSync(ENV_PATH)) throw new Error(`${ENV_PATH} already exists`);
  const facilitator = generatePrivateKey();
  const payer = generatePrivateKey();
  const receiverAuthorizer = generatePrivateKey();
  const text = [
    `AMOY_RPC_URL=${DEFAULT_RPC_URL}`,
    `AMOY_FACILITATOR_PRIVATE_KEY=${facilitator}`,
    `AMOY_PAYER_PRIVATE_KEY=${payer}`,
    `AMOY_RECEIVER_AUTHORIZER_PRIVATE_KEY=${receiverAuthorizer}`,
    ""
  ].join("\n");
  writeFileSync(ENV_PATH, text, { encoding: "utf8", mode: 0o600 });
  chmodSync(ENV_PATH, 0o600);
  console.log(JSON.stringify({
    envPath: ENV_PATH,
    faucetAddress: privateKeyToAccount(facilitator).address,
    faucetUrl: "https://faucet.polygon.technology/"
  }, null, 2));
}

function requirePrivateKey(name: string): Hex {
  const value = process.env[name];
  if (!value || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`missing ${name}`);
  return value as Hex;
}

function artifact(path: string): Artifact {
  return JSON.parse(readFileSync(resolve(process.cwd(), path), "utf8")) as Artifact;
}

function domain() {
  return { name: "x402 Batch Settlement", version: "1", chainId: polygonAmoy.id, verifyingContract: BATCH_ADDRESS } as const;
}

async function rpcResponseBytes(rpcUrl: string, txHash: Hex): Promise<number> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getTransactionReceipt", params: [txHash] })
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`receipt RPC HTTP ${response.status}`);
  return Buffer.byteLength(text, "utf8");
}

async function run(): Promise<void> {
  loadDotenv(process.env, ENV_PATH);
  const rpcUrl = process.env.AMOY_RPC_URL ?? DEFAULT_RPC_URL;
  const facilitator = privateKeyToAccount(requirePrivateKey("AMOY_FACILITATOR_PRIVATE_KEY"));
  const payer = privateKeyToAccount(requirePrivateKey("AMOY_PAYER_PRIVATE_KEY"));
  const receiverAuthorizer = privateKeyToAccount(requirePrivateKey("AMOY_RECEIVER_AUTHORIZER_PRIVATE_KEY"));
  const publicClient = createPublicClient({ chain: polygonAmoy, transport: http(rpcUrl) });
  const wallet = createWalletClient({ account: facilitator, chain: polygonAmoy, transport: http(rpcUrl) }).extend(publicActions);
  if (await publicClient.getChainId() !== polygonAmoy.id) throw new Error("Amoy chain ID mismatch");
  if ((await publicClient.getBytecode({ address: BATCH_ADDRESS })) === undefined) throw new Error("batch contract missing on Amoy");
  const balance = await publicClient.getBalance({ address: facilitator.address });
  if (balance === 0n) throw new Error(`AMOY_POL_REQUIRED:${facilitator.address}`);

  const tokenArtifact = artifact("test/amoy/out/TestDepositToken.sol/TestDepositToken.json");
  const collectorArtifact = artifact("test/amoy/out/TestDepositToken.sol/FixedAmountDepositCollector.json");
  const state = readState();
  let token = state.token;
  if (!token) {
    const nonce = await publicClient.getTransactionCount({ address: facilitator.address });
    if (nonce > 0) {
      const candidate = getContractAddress({ from: facilitator.address, nonce: 0n });
      if (await publicClient.getBytecode({ address: candidate })) token = candidate;
    }
  }
  if (!token) {
    const tokenDeploy = await wallet.deployContract({ abi: tokenArtifact.abi, bytecode: tokenArtifact.bytecode.object });
    const tokenReceipt = await publicClient.waitForTransactionReceipt({ hash: tokenDeploy });
    if (!tokenReceipt.contractAddress) throw new Error("token deployment missing address");
    token = tokenReceipt.contractAddress;
    writeState({ ...state, token });
  }
  let collector = state.collector;
  if (!collector) {
    const collectorDeploy = await wallet.deployContract({
      abi: collectorArtifact.abi,
      bytecode: collectorArtifact.bytecode.object,
      args: [token, 1n]
    });
    const collectorReceipt = await publicClient.waitForTransactionReceipt({ hash: collectorDeploy });
    if (!collectorReceipt.contractAddress) throw new Error("collector deployment missing address");
    collector = collectorReceipt.contractAddress;
    writeState({ token, collector });
  }
  const mintHash = await wallet.writeContract({ address: token, abi: tokenAbi, functionName: "mint", args: [collector, BigInt(CLAIMS)] });
  await publicClient.waitForTransactionReceipt({ hash: mintHash });

  const channels: Channel[] = Array.from({ length: CLAIMS }, (_, index) => ({
    payer: payer.address,
    payerAuthorizer: payer.address,
    receiver: facilitator.address,
    receiverAuthorizer: receiverAuthorizer.address,
    token,
    withdrawDelay: 900,
    salt: toHex(BigInt(index + 1), { size: 32 })
  }));
  const channelIds = channels.map((channel) => hashTypedData({ domain: domain(), types: channelTypes, primaryType: "ChannelConfig", message: channel }));
  for (let offset = 0; offset < channels.length; offset += DEPOSIT_CHUNK) {
    const calls = channels.slice(offset, offset + DEPOSIT_CHUNK).map((channel) => encodeFunctionData({
      abi: batchAbi,
      functionName: "deposit",
      args: [channel, 1n, collector, "0x"]
    }));
    const hash = await wallet.writeContract({ address: BATCH_ADDRESS, abi: batchAbi, functionName: "multicall", args: [calls] });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success") throw new Error(`deposit batch failed at ${offset}`);
  }
  for (const channelId of channelIds) {
    const [channelBalance] = await publicClient.readContract({ address: BATCH_ADDRESS, abi: batchAbi, functionName: "channels", args: [channelId] });
    if (channelBalance !== 1n) throw new Error(`channel deposit mismatch: ${channelId}`);
  }

  const claims = await Promise.all(channels.map(async (channel, index) => {
    const channelId = channelIds[index]!;
    const signature = await payer.signTypedData({ domain: domain(), types: voucherTypes, primaryType: "Voucher", message: { channelId, maxClaimableAmount: 1n } });
    return { voucher: { channel, maxClaimableAmount: 1n }, signature, totalClaimed: 1n };
  }));
  const claimEntries = channelIds.map((channelId) => ({ channelId, maxClaimableAmount: 1n, totalClaimed: 1n }));
  const authorizerSignature = await receiverAuthorizer.signTypedData({
    domain: domain(), types: claimBatchTypes, primaryType: "ClaimBatch", message: { claims: claimEntries }
  });
  const gas = await publicClient.estimateContractGas({ account: facilitator, address: BATCH_ADDRESS, abi: batchAbi, functionName: "claimWithSignature", args: [claims, authorizerSignature] });
  const claimHash = await wallet.writeContract({ address: BATCH_ADDRESS, abi: batchAbi, functionName: "claimWithSignature", args: [claims, authorizerSignature], gas: gas * 12n / 10n });
  const receipt = await publicClient.waitForTransactionReceipt({ hash: claimHash });
  if (receipt.status !== "success") throw new Error("100-claim transaction reverted");
  const rawResponseBytes = await rpcResponseBytes(rpcUrl, claimHash);
  const report = {
    chainId: polygonAmoy.id,
    claimCount: CLAIMS,
    claimTransaction: claimHash,
    collector,
    gasUsed: receipt.gasUsed.toString(),
    logCount: receipt.logs.length,
    rawReceiptBytes: rawResponseBytes,
    token
  };
  mkdirSync(dirname(resolve(process.cwd(), ".amoy/receipt-report.json")), { recursive: true });
  writeFileSync(resolve(process.cwd(), ".amoy/receipt-report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

async function runRevertProbe(): Promise<void> {
  loadDotenv(process.env, ENV_PATH);
  const rpcUrl = process.env.AMOY_RPC_URL ?? DEFAULT_RPC_URL;
  const facilitator = privateKeyToAccount(requirePrivateKey("AMOY_FACILITATOR_PRIVATE_KEY"));
  const payer = privateKeyToAccount(requirePrivateKey("AMOY_PAYER_PRIVATE_KEY"));
  const receiverAuthorizer = privateKeyToAccount(requirePrivateKey("AMOY_RECEIVER_AUTHORIZER_PRIVATE_KEY"));
  const publicClient = createPublicClient({ chain: polygonAmoy, transport: http(rpcUrl) });
  const wallet = createWalletClient({ account: facilitator, chain: polygonAmoy, transport: http(rpcUrl) });
  const token = readState().token ?? getContractAddress({ from: facilitator.address, nonce: 0n });
  const invalidSignature = `0x${"11".repeat(65)}` as Hex;
  const claims = Array.from({ length: CLAIMS }, (_, index) => ({
    voucher: {
      channel: {
        payer: payer.address,
        payerAuthorizer: payer.address,
        receiver: facilitator.address,
        receiverAuthorizer: receiverAuthorizer.address,
        token,
        withdrawDelay: 900,
        salt: toHex(BigInt(index + 1), { size: 32 })
      },
      maxClaimableAmount: 1n
    },
    signature: invalidSignature,
    totalClaimed: 1n
  }));
  const data = encodeFunctionData({
    abi: batchAbi,
    functionName: "claimWithSignature",
    args: [claims, invalidSignature]
  });
  const hash = await wallet.sendTransaction({ to: BATCH_ADDRESS, data, gas: REVERT_PROBE_GAS });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "reverted") throw new Error("expected invalid 100-claim probe to revert");
  const report = {
    chainId: polygonAmoy.id,
    claimCount: CLAIMS,
    claimTransaction: hash,
    calldataBytes: (data.length - 2) / 2,
    gasUsed: receipt.gasUsed.toString(),
    logCount: receipt.logs.length,
    rawReceiptBytes: await rpcResponseBytes(rpcUrl, hash),
    status: receipt.status
  };
  mkdirSync(dirname(resolve(process.cwd(), ".amoy/receipt-report.json")), { recursive: true });
  writeFileSync(resolve(process.cwd(), ".amoy/receipt-report.json"), `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

async function main(): Promise<void> {
  const command = process.argv[2];
  if (command === "init") return initEnv();
  if (command === "run") return run();
  if (command === "revert-probe") return runRevertProbe();
  throw new Error("usage: amoy_batch_receipt.ts <init|run|revert-probe>");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
