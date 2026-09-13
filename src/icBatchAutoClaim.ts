import type { CandidOpt } from "./icBatchChannelStorage";

export type CandidResult<T> = { Ok: T } | { Err: string };
export type AutoClaimStatus = {
  channel_id: string;
  enabled: boolean;
  draining: boolean;
  unclaimed_amount: string;
  unclaimed_count: bigint;
  oldest_unclaimed_at: CandidOpt<bigint>;
  monitored_at: CandidOpt<bigint>;
  withdrawal_deadline: CandidOpt<bigint>;
  transaction: CandidOpt<string>;
  state: string;
  stop_reason: CandidOpt<string>;
  monitor_calls: bigint;
  /** Attached cycles before asynchronous v2 refunds, not net operating cost. */
  monitor_cycles_reserved: bigint;
};

export type IcBatchAutoClaimClient = {
  batch_auto_claim_set_enabled(receiver: string, enabled: boolean): Promise<CandidResult<null>>;
  batch_auto_claim_request(channelId: string): Promise<CandidResult<null>>;
  batch_auto_claim_status(channelId: string): Promise<CandidResult<CandidOpt<AutoClaimStatus>>>;
};

/** Use an authenticated actor with the receiver's existing writer authorization. */
export class IcBatchAutoClaim {
  constructor(private readonly client: IcBatchAutoClaimClient) {}

  async setEnabled(receiver: string, enabled: boolean): Promise<void> {
    unwrap(await this.client.batch_auto_claim_set_enabled(hex(receiver, 20), enabled));
  }

  async requestClaim(channelId: string): Promise<void> {
    unwrap(await this.client.batch_auto_claim_request(hex(channelId, 32)));
  }

  async status(channelId: string): Promise<AutoClaimStatus | undefined> {
    return unwrap(await this.client.batch_auto_claim_status(hex(channelId, 32)))[0];
  }
}

function unwrap<T>(result: CandidResult<T>): T {
  if ("Err" in result) throw new Error(result.Err);
  return result.Ok;
}

function hex(value: string, bytes: number): string {
  if (!new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value)) {
    throw new Error(`expected ${bytes}-byte hex identifier`);
  }
  return value.toLowerCase();
}
