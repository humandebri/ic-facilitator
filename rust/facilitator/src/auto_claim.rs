//! Durable same-channel collection. The signed raw transaction is a write-ahead
//! journal: after it exists we only rebroadcast those bytes, never reuse its nonce.
use super::*;
use crate::batch::{BatchClaimVoucher, BatchVoucherClaim};
use std::collections::BTreeSet;

const THRESHOLD: usize = 100;
const MAX_OUTSTANDING: usize = 200;
const INTERVAL: u64 = 60;
const STALE: u64 = 120;
const CONCURRENCY: usize = 8;

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
struct Charge {
    amount: u128,
    at: u64,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
struct Attempt {
    key: String,
    channel: BatchChannel,
    target: u128,
    from: String,
    contract: String,
    chain_id: u64,
    scope: String,
    fee: u128,
    nonce: Option<u128>,
    raw: Option<String>,
    tx: Option<String>,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
struct Collection {
    seed: BatchChannel,
    charges: Vec<Charge>,
    claimed: u128,
    oldest_legacy: Option<u64>,
    force: bool,
    next_due: u64,
    monitored_at: Option<u64>,
    withdrawal_at: u64,
    balance: u128,
    monitor_calls: u64,
    monitor_cycles_reserved: u128,
    error: Option<String>,
    attempt: Option<Attempt>,
    halted: bool,
    attempt_sequence: u64,
}

#[derive(Clone, Debug, CandidType, CandidDeserialize)]
pub struct AutoClaimStatus {
    pub channel_id: String,
    pub enabled: bool,
    pub draining: bool,
    pub unclaimed_amount: String,
    pub unclaimed_count: u64,
    pub oldest_unclaimed_at: Option<u64>,
    pub monitored_at: Option<u64>,
    pub withdrawal_deadline: Option<u64>,
    pub transaction: Option<String>,
    pub state: String,
    pub stop_reason: Option<String>,
    pub monitor_calls: u64,
    /// Attached cycles before v2 asynchronous refunds; not net execution cost.
    pub monitor_cycles_reserved: u128,
}

thread_local! {
    static POLICIES: RefCell<StableBTreeMap<String, u8, Memory>> = RefCell::new(StableBTreeMap::init(stable_memory(MemoryId::new(11))));
    static COLLECTIONS: RefCell<StableBTreeMap<String, Vec<u8>, Memory>> = RefCell::new(StableBTreeMap::init(stable_memory(MemoryId::new(12))));
    static DUE: RefCell<StableBTreeMap<String, u8, Memory>> = RefCell::new(StableBTreeMap::init(stable_memory(MemoryId::new(13))));
    static BUSY: RefCell<BTreeSet<String>> = const { RefCell::new(BTreeSet::new()) };
    #[cfg(target_arch = "wasm32")]
    static TIMER: RefCell<Option<(ic_cdk_timers::TimerId, u64)>> = const { RefCell::new(None) };
}

fn enabled(receiver: &str) -> bool {
    POLICIES.with(|p| p.borrow().get(&receiver.to_ascii_lowercase()) == Some(1))
}
fn due_key(at: u64, id: &str) -> String {
    format!("{at:020}|{id}")
}
fn get(id: &str) -> Option<Collection> {
    COLLECTIONS.with(|p| p.borrow().get(&id.to_string()).map(decode_stable))
}
fn save(id: &str, value: &Collection) {
    if let Some(old) = get(id) {
        DUE.with(|q| q.borrow_mut().remove(&due_key(old.next_due, id)));
    }
    COLLECTIONS.with(|p| p.borrow_mut().insert(id.to_string(), encode_stable(value)));
    DUE.with(|q| q.borrow_mut().insert(due_key(value.next_due, id), 0));
}
fn remove(id: &str) {
    if let Some(old) = get(id) {
        DUE.with(|q| q.borrow_mut().remove(&due_key(old.next_due, id)));
    }
    COLLECTIONS.with(|p| p.borrow_mut().remove(&id.to_string()));
}
fn amount(value: &str) -> u128 {
    value.parse().expect("validated channel amount")
}
fn fresh(channel: &BatchChannel) -> Collection {
    Collection {
        seed: channel.clone(),
        charges: vec![],
        claimed: 0,
        oldest_legacy: (amount(&channel.charged_cumulative_amount) > 0).then_some(now_seconds()),
        force: amount(&channel.charged_cumulative_amount) > 0,
        next_due: now_seconds(),
        monitored_at: None,
        withdrawal_at: 0,
        balance: 0,
        monitor_calls: 0,
        monitor_cycles_reserved: 0,
        error: None,
        attempt: None,
        halted: false,
        attempt_sequence: 0,
    }
}
fn authorize(receiver: &str) -> Result<String, String> {
    let receiver = normalize_evm_address("receiver", receiver)?;
    if !batch_caller_is_controller()
        && !batch_writer_scope_enabled(batch_update_caller(), &receiver)?
    {
        return Err("caller is not authorized for receiver".into());
    }
    Ok(receiver)
}
fn validate_signer(channel: &BatchChannel) -> Result<(), String> {
    let signer = private_key_address(&env("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY")?)?;
    if !same_address(&signer, &channel.channel_config.receiver_authorizer) {
        return Err("auto claim requires the configured receiver authorizer".into());
    }
    Ok(())
}

pub fn set_enabled(receiver: String, value: bool) -> Result<(), String> {
    let receiver = authorize(&receiver)?;
    if value {
        require_current_seller_acceptance(&receiver)?;
        require_batch_settlement_enabled_except_fee()?;
        private_key_address(&env("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY")?)?;
        private_key_address(&env("FACILITATOR_EVM_PRIVATE_KEY")?)?;
        rpc_config()?;
        claim_fee()?;
    }
    let channels: Vec<BatchChannel> = if value {
        BATCH_CHANNELS.with(|p| {
            p.borrow()
                .iter()
                .map(|entry| decode_stable::<BatchChannel>(entry.value()))
                .filter(|c| same_address(&c.channel_config.receiver, &receiver))
                .collect()
        })
    } else {
        COLLECTIONS.with(|p| {
            p.borrow()
                .iter()
                .map(|entry| decode_stable::<Collection>(entry.value()).seed)
                .filter(|c| same_address(&c.channel_config.receiver, &receiver))
                .collect()
        })
    };
    if value {
        for channel in &channels {
            validate_signer(channel)?;
        }
    }
    let additional = channels
        .iter()
        .filter(|c| get(&c.channel_id).is_none())
        .count() as u64;
    if value
        && COLLECTIONS
            .with(|p| p.borrow().len())
            .saturating_add(additional)
            > 1000
    {
        return Err("auto collection capacity reached".into());
    }
    POLICIES.with(|p| p.borrow_mut().insert(receiver.clone(), u8::from(value)));
    for channel in channels {
        let id = &channel.channel_id;
        let mut collection = get(id).unwrap_or_else(|| fresh(&channel));
        if !value {
            collection.force = true;
        }
        collection.next_due = now_seconds();
        save(id, &collection);
    }
    start_timer();
    Ok(())
}

pub fn request_claim(id: String) -> Result<(), String> {
    validate_channel_id(&id)?;
    let id = id.to_ascii_lowercase();
    let mut collection = get(&id).ok_or("auto collection is not enabled for this channel")?;
    authorize(&collection.seed.channel_config.receiver)?;
    collection.force = true;
    collection.halted = false;
    collection.next_due = now_seconds();
    save(&id, &collection);
    start_timer();
    Ok(())
}

fn claim_fee() -> Result<u128, String> {
    // One voucher claim, regardless of how many off-chain payments it covers.
    let schedule = configured_batch_claim_fee_schedule()?;
    match schedule {
        Some(s) => s
            .claim_1_fee_amount
            .parse()
            .map_err(|_| "invalid claim fee".into()),
        None => batch_fee_for_kind("claim", false),
    }
}
fn stop_reason(c: &Collection, now: u64) -> Option<String> {
    if !enabled(&c.seed.channel_config.receiver) {
        return Some("auto_claim_draining".into());
    }
    if c.withdrawal_at > 0 {
        return Some("withdrawal_requested".into());
    }
    if c.monitored_at
        .is_none_or(|at| now.saturating_sub(at) >= STALE)
    {
        return Some("monitor_stale".into());
    }
    if c.charges.len() >= MAX_OUTSTANDING {
        return Some("collection_backlog".into());
    }
    if !claim_fee()
        .is_ok_and(|fee| seller_credit_balance_for(&c.seed.channel_config.receiver) >= fee)
    {
        return Some("seller_insufficient_credit".into());
    }
    if c.error
        .as_deref()
        .is_some_and(|e| e != "settlement_queue_busy")
    {
        return c.error.clone();
    }
    None
}

pub fn status(id: String) -> Result<Option<AutoClaimStatus>, String> {
    validate_channel_id(&id)?;
    let id = id.to_ascii_lowercase();
    let Some(c) = get(&id) else {
        return Ok(None);
    };
    authorize(&c.seed.channel_config.receiver)?;
    let channel = get_batch_channel(&id).unwrap_or_else(|| c.seed.clone());
    let unclaimed = amount(&channel.charged_cumulative_amount).saturating_sub(c.claimed);
    let on = enabled(&channel.channel_config.receiver);
    Ok(Some(AutoClaimStatus {
        channel_id: id,
        enabled: on,
        draining: !on,
        unclaimed_amount: unclaimed.to_string(),
        unclaimed_count: c.charges.len() as u64,
        oldest_unclaimed_at: if unclaimed == 0 {
            None
        } else {
            c.oldest_legacy.or_else(|| c.charges.first().map(|x| x.at))
        },
        monitored_at: c.monitored_at,
        withdrawal_deadline: (c.withdrawal_at > 0).then(|| {
            c.withdrawal_at
                .saturating_add(channel.channel_config.withdraw_delay)
        }),
        transaction: c.attempt.as_ref().and_then(|a| a.tx.clone()),
        state: if c.attempt.is_some() {
            "sending"
        } else if c.force || c.charges.len() >= THRESHOLD {
            "queued"
        } else {
            "accumulating"
        }
        .into(),
        stop_reason: stop_reason(&c, now_seconds()),
        monitor_calls: c.monitor_calls,
        monitor_cycles_reserved: c.monitor_cycles_reserved,
    }))
}

/// Called only after channel validation and writer authorization. A rejected first
/// reservation registers a monitor seed, but does not accept the pending payment.
pub fn before_update(current: Option<&BatchChannel>, next: &BatchChannel) -> Result<(), String> {
    let id = &next.channel_id;
    if !enabled(&next.channel_config.receiver) && get(id).is_none() {
        return Ok(());
    }
    let existing_pending = current.and_then(|c| c.pending_request.as_ref());
    let creates_pending = next
        .pending_request
        .as_ref()
        .is_some_and(|p| existing_pending.is_none_or(|old| old.pending_id != p.pending_id));
    // Never prevent an already accepted reservation from committing.
    if !creates_pending {
        return Ok(());
    }
    validate_signer(next)?;
    if get(id).is_none() {
        if COLLECTIONS.with(|p| p.borrow().len()) >= 1000 {
            return Err("auto collection capacity reached".into());
        }
        save(id, &fresh(next));
        start_timer();
    }
    let mut collection = get(id).expect("collection exists");
    if collection
        .monitored_at
        .is_none_or(|at| now_seconds().saturating_sub(at) >= STALE)
    {
        collection.monitored_at = None;
        collection.next_due = now_seconds();
        save(id, &collection);
        start_timer();
    }
    if let Some(reason) = stop_reason(&collection, now_seconds()) {
        return Err(reason);
    }
    Ok(())
}

pub fn after_update(current: Option<&BatchChannel>, next: &BatchChannel) {
    let Some(mut c) = get(&next.channel_id) else {
        return;
    };
    let old = current.map_or(0, |c| amount(&c.charged_cumulative_amount));
    let new = amount(&next.charged_cumulative_amount);
    let old_count = c.charges.len();
    c.seed = next.clone();
    if !enabled(&next.channel_config.receiver) {
        c.force = true;
    }
    if new > old {
        c.charges.push(Charge {
            amount: new,
            at: now_seconds(),
        });
    }
    if (old_count < THRESHOLD && c.charges.len() >= THRESHOLD)
        || (c.next_due == u64::MAX
            && (new > old
                || next
                    .pending_request
                    .as_ref()
                    .is_some_and(|p| p.expires_at > now_seconds().saturating_mul(1000))))
    {
        c.next_due = now_seconds();
    }
    save(&next.channel_id, &c);
    start_timer();
}

pub fn before_delete(id: &str) -> Result<(), String> {
    if let Some(c) = get(id) {
        let ch = get_batch_channel(id).unwrap_or(c.seed.clone());
        if c.attempt.is_some()
            || amount(&ch.charged_cumulative_amount) > c.claimed
            || ch
                .pending_request
                .as_ref()
                .is_some_and(|p| p.expires_at > now_seconds().saturating_mul(1000))
        {
            return Err("auto claim must drain before channel deletion".into());
        }
    }
    Ok(())
}
pub fn after_delete(id: &str) {
    remove(id);
}

pub fn record_monitor_outcall(id: &str, cycles: u128) {
    if let Some(mut c) = get(id) {
        c.monitor_calls = c.monitor_calls.saturating_add(1);
        c.monitor_cycles_reserved = c.monitor_cycles_reserved.saturating_add(cycles);
        save(id, &c);
    }
}

fn next_wakeup() -> Option<u64> {
    DUE.with(|q| {
        q.borrow()
            .iter()
            .find(|e| {
                !e.key().starts_with(&format!("{:020}|", u64::MAX))
                    && !BUSY.with(|b| b.borrow().contains(&e.key()[21..]))
            })
            .map(|e| e.key()[..20].parse::<u64>().expect("internal due key"))
    })
}

// Keep an earlier armed deadline even when repeated updates request immediate work.
fn timer_deadline(armed: Option<u64>, next: Option<u64>, now_nanos: u64) -> Option<u64> {
    next.map(|next| {
        let requested = next
            .saturating_mul(1_000_000_000)
            .max(now_nanos.saturating_add(1_000_000_000));
        armed.map_or(requested, |deadline| deadline.min(requested))
    })
}

pub fn start_timer() {
    #[cfg(target_arch = "wasm32")]
    {
        let next = next_wakeup();
        TIMER.with(|timer| {
            let armed = timer.borrow().as_ref().map(|(_, deadline)| *deadline);
            let now = ic_cdk::api::time();
            let deadline = timer_deadline(armed, next, now);
            if deadline == armed {
                return;
            }
            if let Some((old, _)) = timer.borrow_mut().take() {
                ic_cdk_timers::clear_timer(old);
            }
            if let Some(deadline) = deadline {
                let id = ic_cdk_timers::set_timer(
                    std::time::Duration::from_nanos(deadline.saturating_sub(now)),
                    async {
                        TIMER.with(|t| t.borrow_mut().take());
                        dispatch();
                    },
                );
                *timer.borrow_mut() = Some((id, deadline));
            }
        });
    }
}

#[cfg(target_arch = "wasm32")]
struct WorkerGuard(String);
#[cfg(target_arch = "wasm32")]
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        BUSY.with(|b| b.borrow_mut().remove(&self.0));
        start_timer();
    }
}

#[cfg(target_arch = "wasm32")]
fn dispatch() {
    if COLLECTIONS.with(|p| p.borrow().is_empty()) {
        TIMER.with(|t| {
            if let Some((id, _)) = t.borrow_mut().take() {
                ic_cdk_timers::clear_timer(id);
            }
        });
        return;
    }
    let capacity = CONCURRENCY.saturating_sub(BUSY.with(|b| b.borrow().len()));
    let due: Vec<String> = DUE.with(|q| {
        q.borrow()
            .iter()
            .take_while(|e| e.key().as_str() <= due_key(now_seconds(), "~").as_str())
            .take(CONCURRENCY * 2)
            .map(|e| e.key()[21..].to_string())
            .collect()
    });
    for id in due
        .into_iter()
        .filter(|id| !BUSY.with(|b| b.borrow().contains(id)))
        .take(capacity)
    {
        BUSY.with(|b| b.borrow_mut().insert(id.clone()));
        ic_cdk::futures::spawn(async move {
            let _guard = WorkerGuard(id.clone());
            let result = run(&id).await;
            if let Some(mut c) = get(&id) {
                if let Err(error) = result {
                    c.error = Some(error);
                }
                c.next_due = if c.attempt.is_none()
                    && !c.force
                    && get_batch_channel(&id).is_some_and(|ch| {
                        amount(&ch.charged_cumulative_amount) <= c.claimed
                            && ch
                                .pending_request
                                .as_ref()
                                .is_none_or(|p| p.expires_at <= now_seconds().saturating_mul(1000))
                    }) {
                    u64::MAX
                } else {
                    now_seconds().saturating_add(INTERVAL)
                };
                save(&id, &c);
            }
        });
    }
    start_timer();
}

fn reconcile(c: &mut Collection, claimed: u128) {
    c.claimed = c.claimed.max(claimed);
    c.charges.retain(|charge| charge.amount > c.claimed);
    if c.claimed >= amount(&c.seed.charged_cumulative_amount) {
        c.oldest_legacy = None;
    }
}

async fn run(id: &str) -> Result<(), String> {
    let initial = get(id).ok_or("collection removed")?;
    if let Some(a) = initial.attempt.as_ref().filter(|a| a.raw.is_none()) {
        // An interrupted pre-send attempt has no external side effect to verify.
        // Refund it even if monitoring or the current network configuration fails.
        abandon_prepared(id, a);
        return Ok(());
    }
    let channel = get_batch_channel(id);
    if initial.attempt.is_none()
        && initial.monitored_at.is_some()
        && !initial.force
        && channel.as_ref().is_some_and(|ch| {
            amount(&ch.charged_cumulative_amount) <= initial.claimed
                && ch
                    .pending_request
                    .as_ref()
                    .is_none_or(|p| p.expires_at <= now_seconds().saturating_mul(1000))
        })
    {
        return Ok(());
    }
    let config = rpc_config()?;
    let contract = configured_batch_settlement_contract()?;
    let to = parse_address(&contract, "batch contract")?;
    let (balance, claimed, withdrawal) = rpc::auto_claim_channel_state(&config, &to, id).await?;
    let mut c = get(id).ok_or("collection removed")?;
    c.monitored_at = Some(now_seconds());
    c.withdrawal_at = withdrawal;
    c.balance = amount(&balance);
    if !c.halted {
        c.error = None;
    }
    reconcile(&mut c, amount(&claimed));
    if withdrawal > 0 {
        c.force = true;
    }
    save(id, &c);
    // Always resolve an existing journal before considering a new target.
    if c.attempt.is_some() {
        return resume(id, &config).await;
    }
    let Some(channel) = get_batch_channel(id) else {
        if !enabled(&c.seed.channel_config.receiver)
            || c.seed
                .pending_request
                .as_ref()
                .is_none_or(|p| p.expires_at <= now_seconds().saturating_mul(1000))
        {
            remove(id);
        }
        return Ok(());
    };
    let target = amount(&channel.charged_cumulative_amount);
    if target <= c.claimed {
        c.force = false;
        c.oldest_legacy = None;
        save(id, &c);
        if !enabled(&channel.channel_config.receiver)
            && channel
                .pending_request
                .as_ref()
                .is_none_or(|p| p.expires_at <= now_seconds().saturating_mul(1000))
        {
            remove(id);
        }
        return Ok(());
    }
    if c.halted || (!c.force && c.charges.len() < THRESHOLD) {
        return Ok(());
    }
    if target > c.balance {
        return Err("insufficient_channel_balance".into());
    }
    validate_signer(&channel)?;
    validate_batch_channel(id, &channel, &contract)?;
    require_current_seller_acceptance(&channel.channel_config.receiver)?;
    require_batch_settlement_enabled_except_fee()?;
    let fee = claim_fee()?;
    let from = private_key_address(&env("FACILITATOR_EVM_PRIVATE_KEY")?)?;
    let scope = active_settlement_scope(&from, &channel.channel_config.receiver)?;
    let sequence = c
        .attempt_sequence
        .checked_add(1)
        .ok_or("attempt sequence exhausted")?;
    let key = format!("auto-claim:{id}:{target}:{sequence}");
    if !acquire_active_settlement(&scope, &key) {
        return Err("settlement_queue_busy".into());
    }
    if let Err(e) = reserve_seller_credit(&channel.channel_config.receiver, fee) {
        release_active_settlement(&scope, &key);
        return Err(e);
    }
    let attempt = Attempt {
        key,
        channel,
        target,
        from,
        contract,
        chain_id: configured_chain_id(),
        scope,
        fee,
        nonce: None,
        raw: None,
        tx: None,
    };
    c.attempt_sequence = sequence;
    c.attempt = Some(attempt.clone());
    c.force = !enabled(&attempt.channel.channel_config.receiver)
        || (c.force && amount(&c.seed.charged_cumulative_amount) > target);
    save(id, &c);
    record(&attempt, "checking");
    prepare(id, &config, attempt).await
}

fn record(a: &Attempt, state: &str) {
    let args = (
        a.channel.channel_config.payer.clone(),
        a.channel.channel_config.receiver.clone(),
        a.target.to_string(),
        now_seconds(),
        DEFAULT_SETTLEMENT_CACHE_TTL_SECONDS,
    );
    let r = match state {
        "settled" => SettlementRecord::settled(
            a.tx.clone().unwrap_or_default(),
            args.0,
            args.1,
            args.2,
            args.3,
            args.4,
        ),
        "broadcast" => SettlementRecord::broadcast(
            a.tx.clone().unwrap_or_default(),
            args.0,
            args.1,
            args.2,
            args.3,
            args.4,
        ),
        "failed" => SettlementRecord::failed(
            a.tx.clone().unwrap_or_default(),
            "auto claim transaction reverted".into(),
            args.0,
            args.1,
            args.3,
            args.4,
        ),
        _ => SettlementRecord::checking(args.0, args.1, args.2, args.3, args.4),
    };
    insert_batch_settlement(&a.key, r, Some(a.fee));
}
fn store_attempt(id: &str, a: Attempt) {
    let mut c = get(id).expect("collection journal exists");
    c.attempt = Some(a);
    save(id, &c);
}
fn abandon_prepared(id: &str, a: &Attempt) {
    // Only legal before raw bytes have been persisted/sent.
    assert!(a.raw.is_none());
    if let Some(nonce) = a.nonce {
        rollback_reserved_nonce(&a.from, nonce);
    }
    refund_seller_credit(&a.channel.channel_config.receiver, a.fee);
    release_active_settlement(&a.scope, &a.key);
    remove_settlement(&a.key);
    let mut c = get(id).expect("collection exists");
    c.attempt = None;
    c.force = true;
    save(id, &c);
}
async fn prepare(id: &str, config: &RpcConfig, mut a: Attempt) -> Result<(), String> {
    let result = async {
        // Hold the shared lock and persist the fee journal across the read:
        // a manual claim may be mined but not finalized yet.
        let latest =
            rpc::latest_channel_claimed(config, &parse_address(&a.contract, "contract")?, id)
                .await?;
        if latest >= a.target {
            return Err("auto_claim_already_mined".to_string());
        }
        let nonce = pending_nonce(config, &a.from).await?;
        let claim = BatchVoucherClaim {
            voucher: BatchClaimVoucher {
                channel: a.channel.channel_config.clone(),
                max_claimable_amount: a.channel.signed_max_claimable.clone(),
            },
            signature: a.channel.signature.clone(),
            total_claimed: a.target.to_string(),
        };
        let private_key = env("FACILITATOR_EVM_PRIVATE_KEY")?;
        if !same_address(&private_key_address(&private_key)?, &a.from) {
            return Err("signer changed during preparation".into());
        }
        validate_signer(&a.channel)?;
        let raw = rpc::prepare_contract_transaction_reserving(
            config,
            &private_key,
            parse_address(&a.contract, "contract")?,
            encode_batch_claim_calldata(
                &serde_json::from_value(serde_json::json!({"type":"claim", "claims":[claim]}))
                    .map_err(|_| "invalid claim payload")?,
                &env("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY")?,
                &a.contract,
            )?,
            || {
                let reserved = reserve_nonce(&a.from, nonce);
                a.nonce = Some(reserved);
                store_attempt(id, a.clone());
                reserved
            },
        )
        .await
        .map_err(|e| match e {
            SettlementSendError::GasTooExpensive => "gas_too_expensive".to_string(),
            _ => "auto_claim_prepare_failed".to_string(),
        })?;
        a.tx = Some(rpc::prepared_transaction_hash(&raw)?);
        a.raw = Some(raw);
        Ok::<(), String>(())
    }
    .await;
    if let Err(e) = result {
        abandon_prepared(id, &a);
        return if e == "auto_claim_already_mined" {
            Ok(())
        } else {
            Err(e)
        };
    }
    store_attempt(id, a.clone());
    update_active_broadcast(&a.scope, &a.key, a.nonce.unwrap(), a.tx.as_deref().unwrap());
    record(&a, "broadcast");
    // All state above is committed before the external side effect.
    let _ =
        rpc::send_prepared_transaction(config, a.raw.as_deref().unwrap(), a.nonce.unwrap()).await;
    Ok(())
}
async fn resume(id: &str, config: &RpcConfig) -> Result<(), String> {
    let a = get(id).and_then(|c| c.attempt).ok_or("missing journal")?;
    if a.chain_id != configured_chain_id()
        || !same_address(&a.contract, &configured_batch_settlement_contract()?)
    {
        return Err("auto_claim_network_changed".into());
    }
    let outcome = refresh_contract_settlement(
        config,
        a.tx.as_deref().unwrap(),
        &parse_address(&a.contract, "contract")?,
        Some(&a.from),
        &ContractExpectation::Claim,
    )
    .await?;
    match outcome {
        ContractSettlementOutcome::Pending { .. } => {
            let _ =
                rpc::send_prepared_transaction(config, a.raw.as_deref().unwrap(), a.nonce.unwrap())
                    .await;
        }
        ContractSettlementOutcome::Settled { .. } => {
            record(&a, "settled");
            release_active_settlement(&a.scope, &a.key);
            let mut c = get(id).unwrap();
            reconcile(&mut c, a.target);
            c.oldest_legacy = None;
            c.attempt = None;
            save(id, &c);
        }
        ContractSettlementOutcome::Failed { .. } => {
            record(&a, "failed");
            release_active_settlement(&a.scope, &a.key);
            let mut c = get(id).unwrap();
            c.attempt = None;
            c.force = true;
            c.halted = true;
            c.error = Some("claim_reverted_manual_retry_required".into());
            save(id, &c);
        }
    }
    Ok(())
}

#[cfg(test)]
pub fn reset() {
    POLICIES.with(|p| p.borrow_mut().clear_new());
    COLLECTIONS.with(|p| p.borrow_mut().clear_new());
    DUE.with(|p| p.borrow_mut().clear_new());
    BUSY.with(|p| p.borrow_mut().clear());
    rpc::TEST_RPC.with(|q| q.borrow_mut().clear());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    const KEY: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    fn ready<T>(f: impl std::future::Future<Output = T>) -> T {
        let w = std::task::Waker::noop();
        match std::pin::pin!(f)
            .as_mut()
            .poll(&mut std::task::Context::from_waker(w))
        {
            std::task::Poll::Ready(v) => v,
            _ => panic!("unexpected pending"),
        }
    }
    fn response(method: &str, value: Value) {
        rpc::TEST_RPC.with(|q| {
            q.borrow_mut().push_back((
                method.into(),
                Ok(json!({"jsonrpc":"2.0","id":1,"result":value}).to_string()),
            ))
        });
    }
    fn monitor(claimed: u128, withdrawal: u64) {
        response(
            "eth_call",
            json!(format!("0x{:064x}{:064x}", 100_000, claimed)),
        );
        response(
            "eth_call",
            json!(format!("0x{:064x}{:064x}", 100, withdrawal)),
        );
    }
    fn send_inputs() {
        response("eth_call", json!(format!("0x{:064x}{:064x}", 100000, 0)));
        response("eth_getTransactionCount", json!("0x0"));
        response(
            "eth_feeHistory",
            json!({"baseFeePerGas":["0x1","0x1"],"reward":[["0x1"]]}),
        );
        response("eth_estimateGas", json!("0x10000"));
        rpc::TEST_RPC.with(|q| {
            q.borrow_mut()
                .push_back(("eth_sendRawTransaction".into(), Err("response lost".into())))
        });
    }
    fn setup() -> BatchChannel {
        clear_env_values();
        clear_batch_channels();
        clear_active_settlements();
        clear_settlements();
        clear_nonces();
        reset();
        set_env_value(
            "BATCH_SETTLEMENT_CONTRACT",
            CANONICAL_BATCH_SETTLEMENT_CONTRACT,
        );
        set_env_value("BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY", KEY);
        set_env_value(
            "FACILITATOR_EVM_PRIVATE_KEY",
            "0x2222222222222222222222222222222222222222222222222222222222222222",
        );
        set_env_value("BATCH_SETTLEMENT_FEE_AMOUNT", "100");
        set_env_value("POLYGON_RPC_URL", "https://rpc.example.test");
        let address = private_key_address(KEY).unwrap();
        let config = batch::BatchChannelConfig {
            payer: address.clone(),
            payer_authorizer: address.clone(),
            receiver: address.clone(),
            receiver_authorizer: address.clone(),
            token: JPYC_POLYGON_ADDRESS.into(),
            withdraw_delay: 900,
            salt: format!("0x{}", "12".repeat(32)),
        };
        let id = compute_batch_channel_id(&config, CANONICAL_BATCH_SETTLEMENT_CONTRACT).unwrap();
        let channel = BatchChannel {
            channel_id: id.clone(),
            channel_config: config,
            charged_cumulative_amount: "0".into(),
            signed_max_claimable: "0".into(),
            signature: batch::sign_batch_voucher_for_test(
                &id,
                "0",
                KEY,
                CANONICAL_BATCH_SETTLEMENT_CONTRACT,
            ),
            balance: "100000".into(),
            total_claimed: "0".into(),
            withdraw_requested_at: 0,
            refund_nonce: "0".into(),
            onchain_synced_at: None,
            last_request_timestamp: 1,
            pending_request: None,
            revision: 0,
        };
        put_batch_channel(&id, channel.clone()).unwrap();
        put_seller_credit(
            &address,
            SellerCredit {
                credit_atoms: 10000,
                updated_at: now_seconds(),
            },
        );
        batch_set_seller(address.clone(), "active".into()).unwrap();
        batch_set_writer_receiver_scope(
            Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap(),
            address.clone(),
            true,
        )
        .unwrap();
        set_enabled(address, true).unwrap();
        channel
    }
    fn charge(channel: &mut BatchChannel, total: u128) {
        let previous = channel.clone();
        channel.charged_cumulative_amount = total.to_string();
        channel.signed_max_claimable = total.to_string();
        channel.signature = batch::sign_batch_voucher_for_test(
            &channel.channel_id,
            &total.to_string(),
            KEY,
            CANONICAL_BATCH_SETTLEMENT_CONTRACT,
        );
        put_batch_channel(&channel.channel_id, channel.clone()).unwrap();
        after_update(Some(&previous), channel);
    }
    #[test]
    fn hundred_payments_one_claim_and_inflight_payment_survives() {
        let mut ch = setup();
        let id = ch.channel_id.clone();
        for n in 1..100 {
            charge(&mut ch, n);
        }
        monitor(0, 0);
        ready(run(&id)).unwrap();
        assert!(get(&id).unwrap().attempt.is_none());
        charge(&mut ch, 100);
        monitor(0, 0);
        send_inputs();
        ready(run(&id)).unwrap();
        let a = get(&id).unwrap().attempt.unwrap();
        assert_eq!(a.target, 100);
        assert!(a.raw.is_some());
        assert_eq!(seller_credit_balance_for(&ch.channel_config.receiver), 9900);
        charge(&mut ch, 101);
        // Simulate reopening the durable map, as after an upgrade.
        COLLECTIONS
            .with(|p| *p.borrow_mut() = StableBTreeMap::init(stable_memory(MemoryId::new(12))));
        let persisted = get(&id).unwrap().attempt.unwrap();
        assert_eq!(persisted.raw, a.raw);
        monitor(0, 0);
        response(
            "eth_getTransactionReceipt",
            json!({"transactionHash":a.tx,"status":"0x1","blockNumber":"0x10","to":a.contract,"from":a.from}),
        );
        response("eth_blockNumber", json!("0x12"));
        ready(run(&id)).unwrap();
        let c = get(&id).unwrap();
        assert!(c.attempt.is_none());
        assert_eq!(c.charges.len(), 1);
        assert_eq!(c.charges[0].amount, 101);
        assert_eq!(seller_credit_balance_for(&ch.channel_config.receiver), 9900);
    }
    #[test]
    fn withdrawal_bypasses_count_and_preserves_gas_cap() {
        let mut ch = setup();
        charge(&mut ch, 1);
        let id = ch.channel_id.clone();
        monitor(0, now_seconds());
        response("eth_call", json!(format!("0x{:064x}{:064x}", 100000, 0)));
        response("eth_getTransactionCount", json!("0x0"));
        response(
            "eth_feeHistory",
            json!({"baseFeePerGas":["0x1","0xffffffffffffffff"],"reward":[["0x1"]]}),
        );
        response("eth_estimateGas", json!("0x10000"));
        assert_eq!(ready(run(&id)).unwrap_err(), "gas_too_expensive");
        assert_eq!(
            seller_credit_balance_for(&ch.channel_config.receiver),
            10000
        );
        assert!(get(&id).unwrap().attempt.is_none());
        assert_eq!(
            stop_reason(&get(&id).unwrap(), now_seconds()).as_deref(),
            Some("withdrawal_requested")
        );
    }
    #[test]
    fn lost_response_rebroadcasts_same_transaction_without_another_fee() {
        let mut ch = setup();
        charge(&mut ch, 1);
        let id = ch.channel_id.clone();
        request_claim(id.clone()).unwrap();
        monitor(0, 0);
        send_inputs();
        ready(run(&id)).unwrap();
        let raw = get(&id).unwrap().attempt.unwrap().raw;
        monitor(0, 0);
        response("eth_getTransactionReceipt", Value::Null);
        rpc::TEST_RPC.with(|q| {
            q.borrow_mut().push_back((
                "eth_sendRawTransaction".into(),
                Err("response lost again".into()),
            ))
        });
        ready(run(&id)).unwrap();
        assert_eq!(get(&id).unwrap().attempt.unwrap().raw, raw);
        assert_eq!(seller_credit_balance_for(&ch.channel_config.receiver), 9900);
    }
    #[test]
    fn pre_send_upgrade_refunds_once_and_releases_nonce_and_lock() {
        for invalid_config in [false, true] {
            let ch = setup();
            let id = ch.channel_id.clone();
            let from = private_key_address(&env("FACILITATOR_EVM_PRIVATE_KEY").unwrap()).unwrap();
            let scope = active_settlement_scope(&from, &ch.channel_config.receiver).unwrap();
            reserve_seller_credit(&ch.channel_config.receiver, 100).unwrap();
            acquire_active_settlement(&scope, "test");
            let nonce = reserve_nonce(&from, 7);
            let a = Attempt {
                key: "test".into(),
                channel: ch.clone(),
                target: 1,
                from: from.clone(),
                contract: CANONICAL_BATCH_SETTLEMENT_CONTRACT.into(),
                chain_id: configured_chain_id(),
                scope: scope.clone(),
                fee: 100,
                nonce: Some(nonce),
                raw: None,
                tx: None,
            };
            record(&a, "checking");
            store_attempt(&id, a);
            if invalid_config {
                set_env_value("NETWORK_PROFILE", "amoy");
                set_env_value("POLYGON_RPC_URL", "");
                assert!(rpc_config().is_err());
            }
            rpc::TEST_RPC.with(|q| {
                q.borrow_mut()
                    .push_back(("eth_call".into(), Err("monitor offline".into())))
            });
            ready(run(&id)).unwrap();
            assert!(get_settlement("test").is_none());
            assert_eq!(rpc::TEST_RPC.with(|q| q.borrow().len()), 1);
            assert_eq!(get_nonce_state(&from).next_nonce, Some(nonce));
            // A later failed run must not repeat the refund.
            assert!(ready(run(&id)).is_err());
            assert_eq!(
                seller_credit_balance_for(&ch.channel_config.receiver),
                10000
            );
            assert!(get_active_settlement(&scope).is_none());
            assert!(get(&id).unwrap().attempt.is_none());
        }
    }
    #[test]
    fn stale_monitor_and_credit_block_reservations_but_allow_commit() {
        let mut ch = setup();
        let id = ch.channel_id.clone();
        let pending = batch::BatchPendingRequest {
            pending_id: "one".into(),
            signed_max_claimable: "1".into(),
            expires_at: (now_seconds() + 60) * 1000,
        };
        let old = ch.clone();
        ch.pending_request = Some(pending);
        assert_eq!(before_update(Some(&old), &ch).unwrap_err(), "monitor_stale");
        monitor(0, 0);
        ready(run(&id)).unwrap();
        assert!(before_update(Some(&old), &ch).is_ok());
        let mut c = get(&id).unwrap();
        c.withdrawal_at = now_seconds();
        save(&id, &c);
        let mut committed = ch.clone();
        committed.pending_request = None;
        committed.charged_cumulative_amount = "1".into();
        assert!(before_update(Some(&ch), &committed).is_ok());
        c.withdrawal_at = 0;
        save(&id, &c);
        put_seller_credit(
            &ch.channel_config.receiver,
            SellerCredit {
                credit_atoms: 0,
                updated_at: 0,
            },
        );
        assert_eq!(
            before_update(Some(&old), &ch).unwrap_err(),
            "seller_insufficient_credit"
        );
    }
    #[test]
    fn repeated_updates_cannot_postpone_an_armed_timer() {
        let mut deadline = timer_deadline(None, Some(100), 100_000_000_000);
        for now in [
            100_200_000_000,
            100_700_000_000,
            100_999_000_000,
            101_200_000_000,
        ] {
            deadline = timer_deadline(deadline, Some(now / 1_000_000_000), now);
            assert_eq!(deadline, Some(101_000_000_000));
        }
        assert_eq!(
            timer_deadline(deadline, Some(160), 101_200_000_000),
            deadline
        );
        assert_eq!(
            timer_deadline(Some(160_000_000_000), Some(110), 105_000_000_000),
            Some(110_000_000_000)
        );
        assert_eq!(timer_deadline(deadline, None, 101_200_000_000), None);
        // Firing clears the heap deadline; upgrade starts with the same empty state.
        assert_eq!(
            timer_deadline(None, Some(160), 101_200_000_000),
            Some(160_000_000_000)
        );
    }

    #[test]
    fn normal_payments_keep_monitor_schedule_until_threshold_or_idle_wakeup() {
        let mut ch = setup();
        let id = ch.channel_id.clone();
        let scheduled = now_seconds() + INTERVAL;
        let mut c = get(&id).unwrap();
        c.next_due = scheduled;
        c.monitored_at = Some(now_seconds());
        save(&id, &c);
        let old = ch.clone();
        ch.pending_request = Some(batch::BatchPendingRequest {
            pending_id: "payment".into(),
            signed_max_claimable: "0".into(),
            expires_at: (now_seconds() + 60) * 1000,
        });
        before_update(Some(&old), &ch).unwrap();
        after_update(Some(&old), &ch);
        assert_eq!(get(&id).unwrap().next_due, scheduled);
        let old = ch.clone();
        ch.pending_request = None;
        after_update(Some(&old), &ch);
        for total in 1..100 {
            charge(&mut ch, total);
        }
        assert_eq!(get(&id).unwrap().next_due, scheduled);
        charge(&mut ch, 100);
        assert_eq!(get(&id).unwrap().next_due, now_seconds());
        let mut c = get(&id).unwrap();
        c.next_due = scheduled;
        save(&id, &c);
        charge(&mut ch, 101);
        assert_eq!(get(&id).unwrap().next_due, scheduled);
        request_claim(id.clone()).unwrap();
        assert_eq!(get(&id).unwrap().next_due, now_seconds());
        let mut c = get(&id).unwrap();
        c.next_due = u64::MAX;
        save(&id, &c);
        let old = ch.clone();
        ch.pending_request = Some(batch::BatchPendingRequest {
            pending_id: "wake".into(),
            signed_max_claimable: ch.signed_max_claimable.clone(),
            expires_at: (now_seconds() + 60) * 1000,
        });
        before_update(Some(&old), &ch).unwrap();
        after_update(Some(&old), &ch);
        assert_eq!(get(&id).unwrap().next_due, now_seconds());
    }

    #[test]
    fn disabling_never_registers_manual_channels_but_includes_monitor_seeds() {
        let mut manual = setup();
        charge(&mut manual, 1);
        let receiver = manual.channel_config.receiver.clone();
        reset();
        set_enabled(receiver.clone(), false).unwrap();
        set_enabled(receiver.clone(), false).unwrap();
        assert!(status(manual.channel_id.clone()).unwrap().is_none());
        assert!(next_wakeup().is_none());
        assert_eq!(seller_credit_balance_for(&receiver), 10000);
        assert_eq!(active_settlement_count(), 0);
        let mut reserved = manual.clone();
        reserved.pending_request = Some(batch::BatchPendingRequest {
            pending_id: "manual".into(),
            signed_max_claimable: manual.signed_max_claimable.clone(),
            expires_at: (now_seconds() + 60) * 1000,
        });
        before_update(Some(&manual), &reserved).unwrap();
        after_update(Some(&manual), &reserved);
        assert!(get(&manual.channel_id).is_none());

        let mut seed = manual.clone();
        seed.channel_config.salt = format!("0x{}", "34".repeat(32));
        seed.channel_id =
            compute_batch_channel_id(&seed.channel_config, CANONICAL_BATCH_SETTLEMENT_CONTRACT)
                .unwrap();
        let mut c = fresh(&seed);
        c.force = false;
        c.next_due = u64::MAX;
        save(&seed.channel_id, &c);
        assert!(get_batch_channel(&seed.channel_id).is_none());
        for _ in 0..2 {
            set_enabled(receiver.clone(), false).unwrap();
            assert!(get(&manual.channel_id).is_none());
            assert!(get(&seed.channel_id).unwrap().force);
            assert_eq!(get(&seed.channel_id).unwrap().next_due, now_seconds());
            assert_eq!(COLLECTIONS.with(|p| p.borrow().len()), 1);
        }
    }

    #[test]
    fn disabling_drains_and_prevents_deletion_until_claimed() {
        let mut ch = setup();
        charge(&mut ch, 1);
        let id = ch.channel_id.clone();
        set_enabled(ch.channel_config.receiver.clone(), false).unwrap();
        assert!(before_delete(&id).is_err());
        monitor(1, 0);
        ready(run(&id)).unwrap();
        assert!(get(&id).is_none());
        assert!(before_delete(&id).is_ok());
    }
    #[test]
    fn monitor_cost_is_persisted_and_non_controller_is_denied() {
        let mut ch = setup();
        charge(&mut ch, 1);
        let id = ch.channel_id.clone();
        monitor(0, 0);
        ready(run(&id)).unwrap();
        assert_eq!(get(&id).unwrap().monitor_calls, 2);
        assert_eq!(get(&id).unwrap().monitor_cycles_reserved, 200);
        TEST_BATCH_CALLER_IS_CONTROLLER.with(|v| *v.borrow_mut() = false);
        assert!(status(id.clone()).is_err());
        assert!(request_claim(id).is_err());
        reset_test_batch_caller();
    }
    #[test]
    fn duplicate_or_signature_only_updates_do_not_count() {
        let ch = setup();
        after_update(Some(&ch), &ch);
        let mut signature_only = ch.clone();
        signature_only.signed_max_claimable = "10".into();
        after_update(Some(&ch), &signature_only);
        assert!(get(&ch.channel_id).unwrap().charges.is_empty());
    }
    #[test]
    fn manual_settlement_lock_prevents_auto_fee_reservation() {
        let mut ch = setup();
        charge(&mut ch, 1);
        let id = ch.channel_id.clone();
        request_claim(id.clone()).unwrap();
        let from = private_key_address(&env("FACILITATOR_EVM_PRIVATE_KEY").unwrap()).unwrap();
        let scope = active_settlement_scope(&from, &ch.channel_config.receiver).unwrap();
        assert!(acquire_active_settlement(&scope, "manual"));
        monitor(0, 0);
        assert_eq!(ready(run(&id)).unwrap_err(), "settlement_queue_busy");
        assert_eq!(
            seller_credit_balance_for(&ch.channel_config.receiver),
            10000
        );
        assert!(get(&id).unwrap().attempt.is_none());
    }
    #[test]
    fn reverted_transaction_stops_automatic_paid_retries() {
        let mut ch = setup();
        charge(&mut ch, 1);
        let id = ch.channel_id.clone();
        request_claim(id.clone()).unwrap();
        monitor(0, 0);
        send_inputs();
        ready(run(&id)).unwrap();
        let a = get(&id).unwrap().attempt.unwrap();
        monitor(0, 0);
        response(
            "eth_getTransactionReceipt",
            json!({"transactionHash":a.tx,"status":"0x0","blockNumber":"0x10"}),
        );
        response("eth_blockNumber", json!("0x12"));
        ready(run(&id)).unwrap();
        monitor(0, 0);
        ready(run(&id)).unwrap();
        assert!(get(&id).unwrap().halted);
        assert_eq!(seller_credit_balance_for(&ch.channel_config.receiver), 9900);
        request_claim(id.clone()).unwrap();
        assert!(!get(&id).unwrap().halted);
    }
    #[test]
    fn rpc_failure_never_refreshes_monitor_freshness() {
        let mut ch = setup();
        charge(&mut ch, 1);
        let id = ch.channel_id.clone();
        rpc::TEST_RPC.with(|q| {
            q.borrow_mut()
                .push_back(("eth_call".into(), Err("offline".into())))
        });
        assert!(ready(run(&id)).is_err());
        assert!(get(&id).unwrap().monitored_at.is_none());
        assert_eq!(get(&id).unwrap().monitor_calls, 1);
        assert_eq!(
            stop_reason(&get(&id).unwrap(), now_seconds()).as_deref(),
            Some("monitor_stale")
        );
    }
    #[test]
    fn seed_registration_does_not_accept_first_payment() {
        let ch = setup();
        let id = ch.channel_id.clone();
        COLLECTIONS.with(|p| p.borrow_mut().remove(&id));
        BATCH_CHANNELS.with(|p| p.borrow_mut().remove(&id));
        let mut first = ch.clone();
        first.pending_request = Some(batch::BatchPendingRequest {
            pending_id: "first".into(),
            signed_max_claimable: "0".into(),
            expires_at: (now_seconds() + 60) * 1000,
        });
        assert_eq!(before_update(None, &first).unwrap_err(), "monitor_stale");
        assert!(get_batch_channel(&id).is_none());
        monitor(0, 0);
        ready(run(&id)).unwrap();
        assert!(before_update(None, &first).is_ok());
    }
    #[test]
    fn existing_balance_is_flushed_on_enable_without_count_history() {
        let mut ch = setup();
        charge(&mut ch, 7);
        let id = ch.channel_id.clone();
        remove(&id);
        set_enabled(ch.channel_config.receiver.clone(), true).unwrap();
        assert!(get(&id).unwrap().force);
        assert!(get(&id).unwrap().charges.is_empty());
        monitor(0, 0);
        send_inputs();
        ready(run(&id)).unwrap();
        assert_eq!(get(&id).unwrap().attempt.unwrap().target, 7);
    }
    #[test]
    fn signer_mismatch_cannot_enable_collection() {
        let ch = setup();
        set_env_value(
            "BATCH_RECEIVER_AUTHORIZER_PRIVATE_KEY",
            "0x3333333333333333333333333333333333333333333333333333333333333333",
        );
        assert!(set_enabled(ch.channel_config.receiver.clone(), true).is_err());
    }
    #[test]
    fn idle_timer_stops_and_stale_reservation_requeues_monitor() {
        let ch = setup();
        let id = ch.channel_id.clone();
        let mut c = get(&id).unwrap();
        c.next_due = u64::MAX;
        c.monitored_at = Some(now_seconds().saturating_sub(STALE));
        save(&id, &c);
        assert!(next_wakeup().is_none());
        let mut next = ch.clone();
        next.pending_request = Some(batch::BatchPendingRequest {
            pending_id: "wake".into(),
            signed_max_claimable: "0".into(),
            expires_at: (now_seconds() + 60) * 1000,
        });
        assert_eq!(
            before_update(Some(&ch), &next).unwrap_err(),
            "monitor_stale"
        );
        assert_eq!(next_wakeup(), Some(now_seconds()));
        BUSY.with(|b| b.borrow_mut().insert(id.clone()));
        assert!(next_wakeup().is_none());
        BUSY.with(|b| b.borrow_mut().clear());
        assert_eq!(next_wakeup(), Some(now_seconds()));
    }
    #[test]
    fn mined_manual_claim_does_not_charge_again_before_finality() {
        let mut ch = setup();
        charge(&mut ch, 100);
        let id = ch.channel_id.clone();
        request_claim(id.clone()).unwrap();
        monitor(0, 0);
        response("eth_call", json!(format!("0x{:064x}{:064x}", 100000, 100)));
        ready(run(&id)).unwrap();
        assert!(get(&id).unwrap().attempt.is_none());
        assert_eq!(
            seller_credit_balance_for(&ch.channel_config.receiver),
            10000
        );
    }
    #[test]
    fn controller_recovery_cannot_refund_an_auto_claim_twice() {
        let _ch = setup();
        assert_eq!(
            recover_stale_settlement("auto-claim:test:1:1".into()).unwrap_err(),
            "auto claim recovery is owned by the durable collection journal"
        );
    }
}
