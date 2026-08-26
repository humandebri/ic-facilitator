// scripts/amoy_fee_benchmark.ts: Exact/Batchの実トランザクションgasUsedをAmoyで測定する。
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import {
  BATCH_SETTLEMENT_ADDRESS,
  BATCH_SETTLEMENT_DOMAIN,
  claimBatchTypes,
  refundTypes,
  voucherTypes
} from "@x402/evm";
import {
  createPublicClient,
  createWalletClient,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  hashTypedData,
  keccak256,
  http,
  parseAbi,
  parseSignature,
  publicActions,
  toHex
} from "viem";
import type { Address, Hex, TransactionReceipt } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { polygonAmoy } from "viem/chains";

import { loadDotenv } from "./env_file";

const DEFAULT_RPC_URL = "https://polygon-amoy.drpc.org";
const ENV_PATH = resolve(process.cwd(), ".env.amoy.local");
const STATE_PATH = resolve(process.cwd(), ".amoy/fee-benchmark-state.json");
const REPORT_PATH = resolve(process.cwd(), ".amoy/fee-benchmark.json");
const BATCH_ADDRESS = getAddress(BATCH_SETTLEMENT_ADDRESS);
const CLAIM_SAMPLE_COUNTS = [1, 10, 50, 100] as const;
const SAMPLE_CHANNEL_COUNT = CLAIM_SAMPLE_COUNTS.reduce((total, count) => total + count, 0);
const REFUND_SAMPLE_OFFSET = SAMPLE_CHANNEL_COUNT + 3;
const DEPOSIT_CHUNK = 20;
const UNIT = 1n;
export function requiredPayerMintAmount(sampleChannelCount: number): bigint {
  if (!Number.isSafeInteger(sampleChannelCount) || sampleChannelCount < 0) {
    throw new Error("sampleChannelCount must be a non-negative safe integer");
  }
  return 1n + 1n + 2n + BigInt(sampleChannelCount) + BigInt(sampleChannelCount) * 2n;
}

const REQUIRED_PAYER_MINT = requiredPayerMintAmount(SAMPLE_CHANNEL_COUNT);

const batchAbi = parseAbi([
  "function deposit((address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt) config,uint128 amount,address collector,bytes collectorData)",
  "function multicall(bytes[] data) returns (bytes[] results)",
  "function claimWithSignature((((address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt) channel,uint128 maxClaimableAmount) voucher,bytes signature,uint128 totalClaimed)[] voucherClaims,bytes authorizerSignature)",
  "function refundWithSignature((address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt) config,uint128 amount,uint256 nonce,bytes signature)",
  "function settle(address receiver,address token)",
  "function channels(bytes32 channelId) view returns (uint128 balance,uint128 totalClaimed)",
  "function refundNonce(bytes32 channelId) view returns (uint256)",
  "function receivers(address receiver,address token) view returns (uint128 totalClaimed,uint128 totalSettled)"
]);
const tokenAbi = parseAbi([
  "function mint(address to,uint256 amount)",
  "function balanceOf(address account) view returns (uint256)",
  "function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)",
  "function receiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,bytes signature)",
  "function supportsReceiveAuthorization() view returns (bool)"
]);
const collectorAbi = parseAbi([
  "constructor(address batchSettlement)",
  "function x402BatchSettlement() view returns (address)"
]);
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
const authorizationTypes = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" }
  ]
} as const;
const receiveAuthorizationTypes = {
  ReceiveWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" }
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
type State = { token?: Address; collector?: Address };
type ActionReport = {
  action: string;
  calldataBytes: number;
  effectiveGasPriceWei: string;
  feeWei: string;
  gasUsed: string;
  logs: readonly {
    address: Address;
    dataBytes: number;
    topics: readonly Hex[];
  }[];
  postState: Readonly<Record<string, string>>;
  status: "success" | "reverted";
  transaction: Hex;
};

function artifact(path: string): Artifact {
  return JSON.parse(readFileSync(resolve(process.cwd(), path), "utf8")) as Artifact;
}

function readState(): State {
  return existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) as State : {};
}

function writeState(state: State): void {
  mkdirSync(dirname(STATE_PATH), { recursive: true });
  writeFileSync(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`);
}

function requirePrivateKey(name: string): Hex {
  const value = process.env[name];
  if (!value || !/^0x[0-9a-fA-F]{64}$/.test(value)) throw new Error(`missing ${name}`);
  return value as Hex;
}

function batchDomain() {
  return {
    ...BATCH_SETTLEMENT_DOMAIN,
    chainId: polygonAmoy.id,
    verifyingContract: BATCH_ADDRESS
  } as const;
}

function splitSignature(signature: Hex): { v: number; r: Hex; s: Hex } {
  const parsed = parseSignature(signature);
  return {
    r: parsed.r,
    s: parsed.s,
    v: Number(parsed.v ?? BigInt(parsed.yParity + 27))
  };
}

async function run(): Promise<void> {
  loadDotenv(process.env, ENV_PATH);
  const amoyGasPriceGwei = BigInt(process.env.AMOY_MAX_FEE_PER_GAS_GWEI ?? "300");
  if (amoyGasPriceGwei <= 0n) throw new Error("AMOY_MAX_FEE_PER_GAS_GWEI must be positive");
  const amoyMaxFeePerGas = amoyGasPriceGwei * 1_000_000_000n;
  const rpcUrl = process.env.AMOY_RPC_URL ?? DEFAULT_RPC_URL;
  const facilitator = privateKeyToAccount(requirePrivateKey("AMOY_FACILITATOR_PRIVATE_KEY"));
  const payer = privateKeyToAccount(requirePrivateKey("AMOY_PAYER_PRIVATE_KEY"));
  const receiverAuthorizer = privateKeyToAccount(requirePrivateKey("AMOY_RECEIVER_AUTHORIZER_PRIVATE_KEY"));
  const publicClient = createPublicClient({ chain: polygonAmoy, transport: http(rpcUrl) });
  const wallet = createWalletClient({ account: facilitator, chain: polygonAmoy, transport: http(rpcUrl) }).extend(publicActions);

  if (await publicClient.getChainId() !== polygonAmoy.id) throw new Error("Amoy chain ID mismatch");
  if (await publicClient.getBytecode({ address: BATCH_ADDRESS }) === undefined) throw new Error("batch contract missing on Amoy");
  if ((await publicClient.getBalance({ address: facilitator.address })) === 0n) {
    throw new Error(`AMOY_POL_REQUIRED:${facilitator.address}`);
  }

  const tokenArtifact = artifact("test/amoy/out/TestDepositToken.sol/TestEip3009Token.json");
  const collectorArtifact = artifact("test/amoy/out/TestDepositToken.sol/TestErc3009DepositCollector.json");
  const state = readState();
  let token = state.token;
  if (token) {
    try {
      const supported = await publicClient.readContract({
        address: token,
        abi: tokenAbi,
        functionName: "supportsReceiveAuthorization"
      });
      if (supported !== true) token = undefined;
    } catch {
      token = undefined;
    }
  }
  if (!token || await publicClient.getBytecode({ address: token }) === undefined) {
    const hash = await wallet.deployContract({
      abi: tokenArtifact.abi,
      bytecode: tokenArtifact.bytecode.object,
      gas: 2_000_000n,
      maxFeePerGas: amoyMaxFeePerGas,
      maxPriorityFeePerGas: amoyMaxFeePerGas
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (!receipt.contractAddress) throw new Error("token deployment did not return a contract address");
    token = receipt.contractAddress;
    writeState({ ...state, token });
  }
  let collector = state.collector;
  if (collector) {
    try {
      const batchSettlement = await publicClient.readContract({
        address: collector,
        abi: collectorAbi,
        functionName: "x402BatchSettlement"
      });
      if (getAddress(batchSettlement) !== BATCH_ADDRESS) collector = undefined;
    } catch {
      collector = undefined;
    }
  }
  if (!collector || await publicClient.getBytecode({ address: collector }) === undefined) {
    const hash = await wallet.deployContract({
      abi: collectorArtifact.abi,
      bytecode: collectorArtifact.bytecode.object,
      args: [BATCH_ADDRESS],
      gas: 300_000n,
      maxFeePerGas: amoyMaxFeePerGas,
      maxPriorityFeePerGas: amoyMaxFeePerGas
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (!receipt.contractAddress) throw new Error("collector deployment did not return a contract address");
    collector = receipt.contractAddress;
    writeState({ token, collector });
  }
  if (!token || !collector) throw new Error("Amoy benchmark deployment state is incomplete");
  const tokenAddress = token;

  const mintPayer = await wallet.writeContract({
    address: token,
    abi: tokenAbi,
    functionName: "mint",
    args: [payer.address, REQUIRED_PAYER_MINT],
    maxFeePerGas: amoyMaxFeePerGas,
    maxPriorityFeePerGas: amoyMaxFeePerGas
  });
  await publicClient.waitForTransactionReceipt({ hash: mintPayer });
  const payerBalance = await publicClient.readContract({
    address: token,
    abi: tokenAbi,
    functionName: "balanceOf",
    args: [payer.address]
  });
  if (payerBalance < REQUIRED_PAYER_MINT) {
    throw new Error(`payer token balance ${payerBalance} is below required setup amount ${REQUIRED_PAYER_MINT}`);
  }
  async function measure(
    action: string,
    to: Address,
    data: Hex,
    expectedStatus: "success" | "reverted" = "success",
    gas?: bigint,
    readPostState: (() => Promise<Readonly<Record<string, string>>>) | undefined = undefined
  ): Promise<ActionReport> {
    const gasLimit = gas ?? (await publicClient.estimateGas({ account: facilitator.address, to, data })) * 12n / 10n;
    const transaction = await wallet.sendTransaction({
      to,
      data,
      gas: gasLimit,
      maxFeePerGas: amoyMaxFeePerGas,
      maxPriorityFeePerGas: amoyMaxFeePerGas
    });
    const receipt: TransactionReceipt = await publicClient.waitForTransactionReceipt({ hash: transaction });
    if (receipt.status !== expectedStatus) throw new Error(`${action} expected ${expectedStatus}, got ${receipt.status}`);
    const effectiveGasPriceWei = receipt.effectiveGasPrice;
    return {
      action,
      calldataBytes: (data.length - 2) / 2,
      effectiveGasPriceWei: effectiveGasPriceWei.toString(),
      feeWei: (receipt.gasUsed * effectiveGasPriceWei).toString(),
      gasUsed: receipt.gasUsed.toString(),
      logs: receipt.logs.map((log) => ({
        address: log.address,
        dataBytes: (log.data.length - 2) / 2,
        topics: log.topics
      })),
      postState: readPostState ? await readPostState() : {},
      status: receipt.status,
      transaction
    };
  }

  async function channelPostState(channelId: Hex): Promise<Readonly<Record<string, string>>> {
    const [balance, totalClaimed] = await publicClient.readContract({
      address: BATCH_ADDRESS,
      abi: batchAbi,
      functionName: "channels",
      args: [channelId]
    });
    return { balance: balance.toString(), totalClaimed: totalClaimed.toString() };
  }

  async function receiverPostState(): Promise<Readonly<Record<string, string>>> {
    const [totalClaimed, totalSettled] = await publicClient.readContract({
      address: BATCH_ADDRESS,
      abi: batchAbi,
      functionName: "receivers",
      args: [facilitator.address, tokenAddress]
    });
    return { receiverTotalClaimed: totalClaimed.toString(), receiverTotalSettled: totalSettled.toString() };
  }

  async function refundPostState(channelId: Hex): Promise<Readonly<Record<string, string>>> {
    return {
      ...(await channelPostState(channelId)),
      refundNonce: (await publicClient.readContract({
        address: BATCH_ADDRESS,
        abi: batchAbi,
        functionName: "refundNonce",
        args: [channelId]
      })).toString()
    };
  }

  const channelSeed = BigInt(Date.now()) * 1_000n;
  const channels: Channel[] = Array.from({ length: SAMPLE_CHANNEL_COUNT * 2 + 3 }, (_, index) => ({
    payer: payer.address,
    payerAuthorizer: payer.address,
    receiver: facilitator.address,
    receiverAuthorizer: receiverAuthorizer.address,
    token,
    withdrawDelay: 900,
    salt: toHex(channelSeed + BigInt(index), { size: 32 })
  }));
  const channelIds = channels.map((channel) => hashTypedData({ domain: batchDomain(), types: channelTypes, primaryType: "ChannelConfig", message: channel }));
  const tokenDomain = {
    name: "x402 Amoy Test Token",
    version: "1",
    chainId: polygonAmoy.id,
    verifyingContract: token
  } as const;
  const depositData = async (channel: Channel, channelId: Hex, amount: bigint): Promise<Hex> => {
    const validAfter = 0n;
    const validBefore = BigInt(Math.floor(Date.now() / 1000) + 3600);
    const signature = await payer.signTypedData({
      domain: tokenDomain,
      types: receiveAuthorizationTypes,
      primaryType: "ReceiveWithAuthorization",
      message: {
        from: payer.address,
        to: collector,
        value: amount,
        validAfter,
        validBefore,
        nonce: keccak256(encodeAbiParameters(
          [{ type: "bytes32" }, { type: "uint256" }],
          [channelId, BigInt(channel.salt)]
        ))
      }
    });
    const collectorData = encodeAbiParameters(
      [{ type: "uint256" }, { type: "uint256" }, { type: "uint256" }, { type: "bytes" }],
      [validAfter, validBefore, BigInt(channel.salt), signature]
    );
    return encodeFunctionData({
      abi: batchAbi,
      functionName: "deposit",
      args: [channel, amount, collector, collectorData]
    });
  };
  const batchActions: ActionReport[] = [];
  batchActions.push(await measure(
    "batchDeposit",
    BATCH_ADDRESS,
    await depositData(channels[0]!, channelIds[0]!, UNIT),
    "success",
    undefined,
    () => channelPostState(channelIds[0]!)
  ));
  await measure("batchRefundDepositSetup", BATCH_ADDRESS, await depositData(channels[1]!, channelIds[1]!, UNIT));

  const combinedChannel = channels[2]!;
  const combinedChannelId = channelIds[2]!;
  await measure(
    "batchRefundWithClaimDepositSetup",
    BATCH_ADDRESS,
    await depositData(combinedChannel, combinedChannelId, UNIT * 2n)
  );

  const claimChannels = channels.slice(3, REFUND_SAMPLE_OFFSET);
  const claimIds = channelIds.slice(3, REFUND_SAMPLE_OFFSET);
  const refundChannels = channels.slice(REFUND_SAMPLE_OFFSET);
  const refundIds = channelIds.slice(REFUND_SAMPLE_OFFSET);
  const setupDeposits: ActionReport[] = [];
  for (let offset = 0; offset < claimChannels.length; offset += DEPOSIT_CHUNK) {
    const calls = await Promise.all(claimChannels.slice(offset, offset + DEPOSIT_CHUNK).map((channel, index) => {
      const absoluteIndex = offset + index;
      return depositData(channel, claimIds[absoluteIndex]!, UNIT);
    }));
    const data = encodeFunctionData({ abi: batchAbi, functionName: "multicall", args: [calls] });
    setupDeposits.push(await measure(`batchClaimSetupDeposit${offset}`, BATCH_ADDRESS, data));
  }
  for (let offset = 0; offset < refundChannels.length; offset += DEPOSIT_CHUNK) {
    const calls = await Promise.all(refundChannels.slice(offset, offset + DEPOSIT_CHUNK).map((channel, index) => {
      const absoluteIndex = offset + index;
      return depositData(channel, refundIds[absoluteIndex]!, UNIT * 2n);
    }));
    const data = encodeFunctionData({ abi: batchAbi, functionName: "multicall", args: [calls] });
    setupDeposits.push(await measure(`batchRefundWithClaimSetupDeposit${offset}`, BATCH_ADDRESS, data));
  }

  const signClaim = async (channel: Channel, channelId: Hex, totalClaimed: bigint) => ({
    voucher: { channel, maxClaimableAmount: totalClaimed },
    signature: await payer.signTypedData({
      domain: batchDomain(),
      types: voucherTypes,
      primaryType: "Voucher",
      message: { channelId, maxClaimableAmount: totalClaimed }
    }),
    totalClaimed
  });
  async function claimCall(offset: number, count: number): Promise<Hex> {
    const claims = await Promise.all(
      claimChannels.slice(offset, offset + count).map((channel, index) =>
        signClaim(channel, claimIds[offset + index]!, UNIT)
      )
    );
    const claimAuthorizerSignature = await receiverAuthorizer.signTypedData({
      domain: batchDomain(),
      types: claimBatchTypes,
      primaryType: "ClaimBatch",
      message: {
        claims: claimIds.slice(offset, offset + count).map((channelId) => ({
          channelId,
          maxClaimableAmount: UNIT,
          totalClaimed: UNIT
        }))
      }
    });
    return encodeFunctionData({
      abi: batchAbi,
      functionName: "claimWithSignature",
      args: [claims, claimAuthorizerSignature]
    });
  }

  let sampleOffset = 0;
  for (const count of CLAIM_SAMPLE_COUNTS) {
    batchActions.push(await measure(`batchClaim${count}`, BATCH_ADDRESS, await claimCall(sampleOffset, count)));
    sampleOffset += count;
  }
  batchActions.push(await measure(
    "batchSettle",
    BATCH_ADDRESS,
    encodeFunctionData({ abi: batchAbi, functionName: "settle", args: [facilitator.address, token] }),
    "success",
    undefined,
    receiverPostState
  ));
  batchActions.push(await measure(
    "batchSettleNoop",
    BATCH_ADDRESS,
    encodeFunctionData({ abi: batchAbi, functionName: "settle", args: [facilitator.address, token] }),
    "success",
    undefined,
    receiverPostState
  ));

  const refundSignature = await receiverAuthorizer.signTypedData({
    domain: batchDomain(),
    types: refundTypes,
    primaryType: "Refund",
    message: { channelId: channelIds[1]!, nonce: 0n, amount: UNIT }
  });
  batchActions.push(await measure(
    "batchRefund",
    BATCH_ADDRESS,
    encodeFunctionData({ abi: batchAbi, functionName: "refundWithSignature", args: [channels[1]!, UNIT, 0n, refundSignature] }),
    "success",
    undefined,
    () => refundPostState(channelIds[1]!)
  ));

  async function refundCall(offset: number, count: number): Promise<Hex> {
    const claims = await Promise.all(refundChannels.slice(offset, offset + count).map((channel, index) =>
      signClaim(channel, refundIds[offset + index]!, UNIT)
    ));
    const claimAuthorizerSignature = await receiverAuthorizer.signTypedData({
      domain: batchDomain(),
      types: claimBatchTypes,
      primaryType: "ClaimBatch",
      message: {
        claims: refundIds.slice(offset, offset + count).map((channelId) => ({
          channelId,
          maxClaimableAmount: UNIT,
          totalClaimed: UNIT
        }))
      }
    });
    const claimCall = encodeFunctionData({
      abi: batchAbi,
      functionName: "claimWithSignature",
      args: [claims, claimAuthorizerSignature]
    });
    const refundCalls = await Promise.all(refundChannels.slice(offset, offset + count).map(async (channel, index) => {
      const signature = await receiverAuthorizer.signTypedData({
        domain: batchDomain(),
        types: refundTypes,
        primaryType: "Refund",
        message: { channelId: refundIds[offset + index]!, nonce: 0n, amount: UNIT }
      });
      return encodeFunctionData({
        abi: batchAbi,
        functionName: "refundWithSignature",
        args: [channel, UNIT, 0n, signature]
      });
    }));
    return encodeFunctionData({ abi: batchAbi, functionName: "multicall", args: [[claimCall, ...refundCalls]] });
  }
  let refundSampleOffset = 0;
  for (const count of CLAIM_SAMPLE_COUNTS) {
    batchActions.push(await measure(
      `batchRefundWithClaim${count}`,
      BATCH_ADDRESS,
      await refundCall(refundSampleOffset, count),
      "success",
      undefined,
      () => refundPostState(refundIds[refundSampleOffset]!)
    ));
    refundSampleOffset += count;
  }

  const combinedClaimCall = await (async () => {
    const claim = await signClaim(combinedChannel, combinedChannelId, UNIT);
    const authorizerSignature = await receiverAuthorizer.signTypedData({
      domain: batchDomain(),
      types: claimBatchTypes,
      primaryType: "ClaimBatch",
      message: { claims: [{ channelId: combinedChannelId, maxClaimableAmount: UNIT, totalClaimed: UNIT }] }
    });
    return encodeFunctionData({
      abi: batchAbi,
      functionName: "claimWithSignature",
      args: [[claim], authorizerSignature]
    });
  })();
  const combinedRefundSignature = await receiverAuthorizer.signTypedData({
    domain: batchDomain(),
    types: refundTypes,
    primaryType: "Refund",
    message: { channelId: combinedChannelId, nonce: 0n, amount: UNIT }
  });
  const combinedRefundCall = encodeFunctionData({
    abi: batchAbi,
    functionName: "refundWithSignature",
    args: [combinedChannel, UNIT, 0n, combinedRefundSignature]
  });
  batchActions.push(await measure(
    "batchRefundWithClaim",
    BATCH_ADDRESS,
    encodeFunctionData({ abi: batchAbi, functionName: "multicall", args: [[combinedClaimCall, combinedRefundCall]] }),
    "success",
    undefined,
    () => refundPostState(combinedChannelId)
  ));

  const validAfter = 0n;
  const validBefore = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const exactNonce = toHex(channelSeed + 999n, { size: 32 });
  const exactMessage = {
    from: payer.address,
    to: facilitator.address,
    value: UNIT,
    validAfter,
    validBefore,
    nonce: exactNonce
  } as const;
  const exactSignature = await payer.signTypedData({
    domain: { name: "x402 Amoy Test Token", version: "1", chainId: polygonAmoy.id, verifyingContract: token },
    types: authorizationTypes,
    primaryType: "TransferWithAuthorization",
    message: exactMessage
  });
  const { v, r, s } = splitSignature(exactSignature);
  const exactData = encodeFunctionData({
    abi: tokenAbi,
    functionName: "transferWithAuthorization",
    args: [payer.address, facilitator.address, UNIT, validAfter, validBefore, exactNonce, v, r, s]
  });
  const exactPostState = async (): Promise<Readonly<Record<string, string>>> => {
    const [payerBalance, facilitatorBalance] = await Promise.all([
      publicClient.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [payer.address] }),
      publicClient.readContract({ address: token, abi: tokenAbi, functionName: "balanceOf", args: [facilitator.address] })
    ]);
    return { payerBalance: payerBalance.toString(), facilitatorBalance: facilitatorBalance.toString() };
  };
  const exactActions = [await measure("exact", token, exactData, "success", undefined, exactPostState)];
  exactActions.push(await measure("exactNonceReplay", token, exactData, "reverted", 150_000n, exactPostState));

  const report = {
    chainId: polygonAmoy.id,
    generatedAt: new Date().toISOString(),
    network: "amoy",
    batchContract: BATCH_ADDRESS,
    token,
    collector,
    actions: {
      exact: exactActions,
      batch: batchActions,
      setupDeposits
    }
  };
  mkdirSync(dirname(REPORT_PATH), { recursive: true });
  writeFileSync(REPORT_PATH, `${JSON.stringify(report, null, 2)}\n`);
  console.log(JSON.stringify(report, null, 2));
}

function initEnv(): void {
  if (existsSync(ENV_PATH)) throw new Error(`${ENV_PATH} already exists`);
  const facilitator = generatePrivateKey();
  const payer = generatePrivateKey();
  const receiverAuthorizer = generatePrivateKey();
  writeFileSync(ENV_PATH, [
    `AMOY_RPC_URL=${DEFAULT_RPC_URL}`,
    `AMOY_FACILITATOR_PRIVATE_KEY=${facilitator}`,
    `AMOY_PAYER_PRIVATE_KEY=${payer}`,
    `AMOY_RECEIVER_AUTHORIZER_PRIVATE_KEY=${receiverAuthorizer}`,
    ""
  ].join("\n"), { encoding: "utf8", mode: 0o600 });
  console.log(JSON.stringify({
    envPath: ENV_PATH,
    faucetAddress: privateKeyToAccount(facilitator).address,
    faucetUrl: "https://faucet.polygon.technology/"
  }, null, 2));
}

async function main(): Promise<void> {
  const command = process.argv[2];
  if (command === "init") return initEnv();
  if (command === "run") return run();
  throw new Error("usage: amoy_fee_benchmark.ts <init|run>");
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
