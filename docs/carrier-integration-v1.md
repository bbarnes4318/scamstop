# Carrier integration contract, v1

Status: implemented in ScamStop (this repository). Switch-side and portal-side changes are
specified here and in `deploy/carrier/opensips-fraud-gate.cfg`; they still have to be
applied in `bbarnes4318/new-switch` and `bbarnes4318/voip-portal` and validated with the
switch integration tests listed in §11.

This contract covers three systems:

| System | Repository | Role in v1 |
|---|---|---|
| **Carrier SBC** | `bbarnes4318/new-switch` (OpenSIPS 3.6, `config/opensips-production.cfg`) | Authenticates every call, resolves the customer, stores attribution on the dialog, rejects new calls from denied customers, ends dialogs on request |
| **VoIP portal** | `bbarnes4318/voip-portal` | **Authoritative** for customer ids, reseller relationships, source IPs, entry IPs, dial prefixes and routing (`sbc:cust:*`, `sbc:entry:*`, `sbc:portal:*`) |
| **ScamStop** | `bbarnes4318/scamstop` | Listens, detects, decides; terminates calls; owns `sbc:fraud:v1:*` |

The existing carrier SBC stays. ScamStop's standalone hosted SBC (`deploy/sbc/`) is **not** used
in this mode and nothing in the switch configuration is replaced.

## 1. Enabling carrier mode in ScamStop

```yaml
# /etc/scamstop/config.yaml
carrier:
  enabled: true
  operator: PVN
  policy: {enforce: true, warn_mode: warn_then_hangup}
platform: {type: opensips}
proxy: {type: opensips, fifo: /run/opensips/opensips_fifo, reply_dir: /tmp}
```

Effects (all enforced in code, see `scamstop/policy.py`, `scamstop/tenants.py`, `scamstop/ui.py`):

* **Mandatory policy.** `carrier.policy` decides dry-run and warning mode for every call. The
  global `dry_run`, hosted tenants' `dry_run`/`warn_mode`, and every customer/tenant API
  (`POST /api/me`, `POST /api/tenants/<id>`) cannot weaken it; such requests get HTTP 403.
  The `carrier` section is not editable from the panel at all (config file only).
  `carrier.policy.enforce: false` is the single, explicit, operator-only advisory switch.
  An unknown `warn_mode` falls back to `warn_then_hangup`, never to something weaker.
* **Registry is read-only.** ScamStop never writes or deletes `sbc:cust:*`, `sbc:entry:*` or
  `sbc:route:*`. Tenant sync, IP add/remove, tenant delete and the panel's Customers page all
  refuse or no-op. Self-service signup is closed (accounts live in the portal).
* **Identity comes from the switch** (§3). The SIP Contact host is no longer used to decide
  whether a call is monitored or whom it belongs to; every call on the switch is monitored.
* Restart required after changing `carrier.*` (it is a restart section).

Standalone mode (`carrier.enabled: false`, the default) behaves as before, including an
operator's explicit `dry_run: true` and hosted tenants' own settings. New hosted tenants still
start watch-only there unless `hosted.new_tenant_dry_run: false`.

## 2. Ownership and permitted writers

| Keys | Owner | Writers | Readers |
|---|---|---|---|
| `sbc:cust:*`, `sbc:entry:*`, `sbc:portal:*` | portal | portal sync (`sbc/opensips-portal-sync.sh`) only | switch, ScamStop (read) |
| `sbc:fraud:v1:deny:customer:<id>` | ScamStop | ScamStop only (automatic escalation, `scamstop fraud …`, panel `POST /api/fraud`, requests stream consumer) | switch, portal, ScamStop |
| `sbc:fraud:v1:requests` | ScamStop | PVN fraud staff tools and the portal (XADD only) | ScamStop |
| `sbc:fraud:v1:audit`, `:rev`, `:epoch`, `:req:*`, `:ack:*`, `:ev:*`, `:children:*` | ScamStop | ScamStop only | anyone (read) |
| `sbc:block:*`, `sbc:strike:*`, `sbc:dnc` | ScamStop | ScamStop | ScamStop (the switch does not read these today) |

Rules:

1. **An ordinary portal sync never clears fraud blocks.** The portal sync deletes only keys
   matching `sbc:cust:*`, `sbc:entry:*` and `sbc:portal:*`; `sbc:fraud:v1:*` is outside every
   pattern it touches, and deny records have **no Redis TTL**. Portal changes to a customer
   (suspension, funds, new IPs) never remove a fraud block, and a fraud block never edits the
   registry. (Test: `tests/test_daemon_carrier.py::test_portal_sync_cannot_clear_fraud_blocks`.)
2. The portal must not write `sbc:fraud:v1:deny:*` directly. It asks through the requests
   stream (§6) so every change is validated, idempotent, revisioned and audited.
3. The switch never writes `sbc:fraud:v1:*`.
4. `sbc:cust:disabled` (the switch kill switch) does not disable fraud checks.

## 3. Trusted call attribution (switch → ScamStop)

The switch already resolves every registry call in `route[CUSTOMER_REGISTRY]`. It stores the
result on the dialog with `$dlg_val()` immediately after `create_dialog("B")`:

| Dialog value | Meaning | Format (validated by ScamStop, `scamstop/attribution.py`) |
|---|---|---|
| `fa_v` | contract version | exactly `1` |
| `fa_cust` | customer that placed the call — for a reseller's customer, the **child** | `^[0-9]{1,18}$`, not all zeros |
| `fa_parent` | reseller above it, when applicable | same as customer id, ≠ `fa_cust` |
| `fa_src` | SIP source IP the switch authenticated (`$si`) | IPv4 |
| `fa_entry` | switch socket the call arrived on (`$socket_in(ip)`) | IPv4 |
| `fa_ep` | resolved endpoint for prefix-routed reseller customers | `^pfx:[0-9]{1,18}:[0-9]{3,6}$`; its reseller id must equal `fa_parent` |

Dialog identifiers come from the dialog module itself: `ID` (the `dialog_id` that
`dlg_end_dlg` takes), `callid`, `caller_tag`, `callee_tag`.

ScamStop reads them with the dialog module's MI command **`dlg_list_ctx`** (which prints each
dialog's values; plain `dlg_list` does not) over the existing `mi_fifo`
(`/run/opensips/opensips_fifo`). Value names are configurable under
`carrier.attribution.values`.

Trust rules:

* All fields valid → `trusted`. Account-level actions (escalation, deny checks) use only
  trusted attribution.
* Missing values (legacy path, `127.0.0.1`, Dograh calls, registry fallback), unknown version, or
  any invalid field → `untrusted:<reason>`, counted in `scamstop_attribution_untrusted`. The
  call is still monitored and can still be ended **as a call**; it never escalates an account.
* Call-ID host, media IP, caller ID and dialer tags (`CNX…_`) remain **supporting indicators**
  (center strikes, block lists, evidence logs). They never select a customer account.
  `centers.never_block_customer_ip` still applies to center blocking, and in carrier mode the
  `source_ip` strategy and `src` gate checks are disabled.

Switch changes needed for `fa_parent` on a reseller customer that sends from its **own** IP
(not by prefix): the `sbc:cust` record does not carry the reseller id today. The portal adds it
as an 8th field (§8); the switch reads it with `$(var(rec){s.select,7,|})`.

## 4. Deny records

`sbc:fraud:v1:deny:customer:<customer_id>` — a Redis **HASH**:

| Field | Type | Meaning |
|---|---|---|
| `state` | `blocked` \| `quarantined` | `quarantined` = automatic or provisional, pending PVN review. `blocked` = confirmed by PVN. **Both** deny new calls and terminate active ones. |
| `reason_code` | `^[a-z0-9_]{1,40}$` | e.g. `auto_escalation`, `children_quarantined`, `confirmed_fraud`, `operator_review` |
| `case_id` | `^[A-Za-z0-9._:-]{1,64}$` | PVN case / ticket reference; `auto-<id>-<bucket>` for automatic ones |
| `revision` | integer | from the global counter `sbc:fraud:v1:rev`; strictly increasing across all changes |
| `updated_at` | integer | Unix epoch **seconds**, UTC, from Redis `TIME` at write time |
| `expires_at` | integer | Unix epoch **seconds**, UTC; **`0` = no automatic expiry** |
| `actor`, `request_id` | string | who made the change and with which request |

**Timestamp units:** every timestamp in `sbc:fraud:v1:*` is integer Unix epoch seconds (UTC).
Never milliseconds. The switch compares `expires_at` against `$Ts` (seconds).

A record is **active** iff `state ∈ {blocked, quarantined}` and (`expires_at == 0` or
`expires_at > now`). An expired record is inactive immediately for every reader, even before
ScamStop's sweeper deletes it (with an `expired` audit entry). Deny records carry no Redis TTL,
so they are never lost silently to key expiry.

Precedence: a check denies a call if the **customer** or its **parent** has an active record.
Blocking a reseller denies all of its children's calls; blocking a child never affects the
reseller or its siblings.

## 5. Changes: idempotency, staleness, concurrency

Every change runs as one Lua script (`scamstop/fraud.py`, loaded with `SCRIPT LOAD` /
`EVALSHA` via redis-py `register_script`). Untrusted values travel only as `KEYS`/`ARGV`;
nothing is concatenated into script text or into any shell command. All values are validated
before the call.

* **Idempotent:** each change carries a `request_id` (`^[A-Za-z0-9._:-]{8,80}$`). The first
  result is stored at `sbc:fraud:v1:req:<request_id>` for 7 days; a retry returns that result
  (`duplicate: true`) and changes nothing.
* **Stale actions:** a block/quarantine may carry `based_on_revision`; if the record has moved
  past it, the result is `stale` and nothing changes.
* **No silent downgrade:** a quarantine never replaces an active block (`kept_stronger`).
* **Unblock:** requires `expected_revision` — the revision the operator reviewed. If anything
  changed since (a new block arrived), the result is `conflict` and the block stays.
  Concurrent block/unblock therefore can never lose a newer block
  (`tests/test_fraud.py::test_concurrent_block_and_unblock_never_lose_a_newer_block`).
* **Results:** `applied`, `duplicate`, `stale`, `kept_stronger`, `conflict`, `absent`, `rejected`.
* **Epoch:** every applied change increments `sbc:fraud:v1:epoch` (and block-list changes
  increment `sbc:block:epoch`); ScamStop re-checks all active calls when either changes (§7).

## 6. Enforcement requests and audit

Permitted writers queue requests with `XADD sbc:fraud:v1:requests * field value …`:

| Field | Required | Format |
|---|---|---|
| `op` | yes | `block` \| `quarantine` \| `unblock` |
| `customer_id` | yes | customer id |
| `case_id`, `request_id`, `actor` | yes | see §4/§5 (`actor`: `^[A-Za-z0-9._@:-]{1,64}$`) |
| `reason_code` | block/quarantine | see §4 (`unblocked` default for unblock) |
| `expires_at` | no | epoch seconds, `0` = never; must be in the future and < 10 years |
| `based_on_revision` | no | integer |
| `expected_revision` | unblock | integer |

ScamStop consumes the stream with consumer group `scamstop` (at-least-once; replays are safe
because of `request_id`). Invalid requests are acknowledged and recorded as `rejected` in the
audit stream. Operators can also use `scamstop fraud block|quarantine|unblock|list|show|audit`
or the panel's `/api/fraud`.

`sbc:fraud:v1:audit` (stream, capped at `carrier.audit_maxlen`, default 100 000) gets one entry
per change or refusal: `op`, `customer_id`, `state`, `reason_code`, `case_id`, `expires_at`,
`revision`, `actor`, `request_id`, `result`, `ts` (epoch seconds), `expected_revision`.

## 7. Enforcement on calls and acknowledgements

**New calls.** The switch checks deny records for `fa_cust` and `fa_parent` in
`route[CUSTOMER_REGISTRY]` (reference: `deploy/carrier/opensips-fraud-gate.cfg`, one
`cache_raw_query` `EVAL`, the same mechanism the switch already uses) and answers
`403 Forbidden`, logging `SBC-REJECT reason=FRAUD_DENY` and `sbc:reject_fraud_deny`.

**Active calls.** ScamStop's gatekeeper re-checks every active call whenever
`sbc:block:epoch` or `sbc:fraud:v1:epoch` changes, and at least every `monitor.recheck_s`
(default 30 s). A call that was clean when it started does not survive a new block or a new
quarantine of its customer or reseller. When an account is quarantined automatically, its
other active calls are ended on the next poll.

**Termination outcomes** (`scamstop/enforcement.py`) are recorded separately and never assumed:

| State | Meaning |
|---|---|
| `requested` | a kill/deny decision was made for the call |
| `warning_started` | the warning began playing (warn modes) |
| `termination_requested` | `dlg_end_dlg dialog_id=<ID>` was sent (attempt *n*) |
| `termination_confirmed` | `dlg_list callid=<Call-ID>` no longer lists that dialog ID |
| `failed` | still listed after `1 + enforcement.end_retries` requests, each checked at `enforcement.confirm_delays_s` |
| `unknown` | the switch could not answer the check (MI error / timeout) |

Each transition is written to `evidence.enforcement_log` and to
`sbc:fraud:v1:ack:<Call-ID>` (HASH: `state`, `updated_at`, `dialog_id`, `reason`, `attempts`,
`customer_id`, `error`; TTL `enforcement.ack_ttl_s`, default 1 day). `failed`/`unknown` are
counted (`scamstop_enforce_failed`, `scamstop_enforce_unknown`), mark protection as degraded,
and the gatekeeper tries again after `monitor.recheck_s`.

## 8. Portal (voip-portal) changes required

1. **Registry record, 8th field `reseller_id`.** `buildRegistry` adds the parent customer id
   (or `-`) after `reseller_tag`; `formatCustValue` appends it; the sync script's
   `cust_entries` jq and grep gain `\|([0-9]{1,18}|-)` at the end. The switch's existing
   `f(r, i)` field reader is index-based, so fields 0–6 keep their meaning.
2. **Read-only fraud view.** Show `sbc:fraud:v1:deny:customer:<id>` (state, reason, case,
   expiry) on the customer page and the reseller's customer list; never write it directly.
3. **Requests.** PVN fraud staff actions go to `sbc:fraud:v1:requests` with a fresh
   `request_id` and, for unblock, the displayed `revision` as `expected_revision`.
4. **No change to sync deletion patterns.** They must never include `sbc:fraud:*`.

## 9. Failure handling

| Situation | Switch | ScamStop |
|---|---|---|
| Redis unreachable | registry and fraud checks fail **open** (existing policy), logs `SBC-FRAUD-ERROR`, `sbc:fraud_check_error` | deny checks raise → counted as `fraud_store_errors`, protection `degraded`; calls keep being monitored and phrase/smart kills still work |
| Portal sync dead | `sbc:portal:*` expire after `max_age_seconds`; `sbc:cust:*` kept | unaffected: deny records have no TTL |
| `sbc:portal:pfx:*` expired mid-day | prefix calls fall back to the reseller's own identity (no `fa_ep`) | attribution is still trusted for the reseller; the child cannot be distinguished, so escalation evidence lands on the reseller id — a reason to keep `parent.enabled` evidence thresholds conservative |
| Dialog values missing/invalid | — | `untrusted`, monitored, no account action |
| MI FIFO slow/unavailable | — | termination outcomes become `unknown`, retried on recheck; poll errors surfaced as `platform_error` |
| LLM server down/slow/invalid | — | bounded; classifier-only fallback, visibly labelled `(llm unavailable)` / `(llm overloaded)` |
| Delayed verdict after call ended / Call-ID reused | — | dropped (`smart_llm_stale`); generation = (Call-ID, dialog ID, listener start) |
| Retried request | — | `duplicate` result, no change |
| Concurrent block + unblock | — | revision check: unblock of an older revision → `conflict` |

## 10. Account escalation (ScamStop)

`scamstop/escalation.py`, configured under `carrier.escalation`:

* Only kills with **strong** evidence count: a strong phrase rule (caller or victim side), a
  corroborated combination of context signals, or a smart-check kill. Context/weak phrase
  matches (e.g. "hi grandma", "public defender", "Wells Fargo fraud department"),
  off-campaign hits and block-list/feed matches never count. A weak phrase match alone can
  therefore never suspend an account.
* Requires trusted attribution (`carrier.attribution.require_for_escalation`).
* Quarantine needs `quarantine_after` (3) distinct terminated calls within `window_s` (24 h)
  covering `min_evidence_kinds` (2) of `phrase_caller`, `phrase_victim`, `corroborated`, `smart`.
* The account escalated is `fa_cust` — the reseller's **child**, never the reseller.
  The reseller is escalated only if `parent.enabled` (off by default) and
  `parent.children_quarantined` children were quarantined; otherwise it is flagged for review.
* Result: `state=quarantined`, `actor=scamstop`, `reason_code=auto_escalation`,
  `case_id=auto-<id>-<window bucket>`, `request_id=auto:<id>:<bucket>`, `expires_at` =
  now + `quarantine_ttl_s` or `0` (until reviewed). Because the request id is per window, an
  operator's unblock is not immediately undone by the same window's evidence.
* Shared-feed indicators (caller IDs, IPs) are external evidence with their own confidence
  (`feed:<rules> x<reporters>` in the block reason, `origin: feed` in evidence) and only ever
  act on individual calls.

## 11. Integration tests that require the switch (not run in CI)

Run on the lab SBC (`sbc-lab-fsn1`), with SIPp, never on production:

1. `opensips -C` accepts the config with the fragments from `deploy/carrier/opensips-fraud-gate.cfg`.
2. `opensips-cli -x mi dlg_list_ctx` shows `values` with `fa_v`, `fa_cust`, … for a registry
   call, and the JSON shape matches `attribution._values()` (list of one-entry objects).
3. Direct customer, reseller-by-prefix (`101#1212…`) and reseller-customer-by-own-IP calls each
   produce the expected `fa_cust` / `fa_parent` / `fa_ep`.
4. With `sbc:fraud:v1:deny:customer:<child>` set: new INVITE → `403`, `sbc:reject_fraud_deny`
   increments; the reseller's own calls still pass. With the reseller denied: children → 403.
5. `expires_at` in the past → calls pass; `expires_at=0` → denied.
6. Redis stopped → calls pass (fail open) and `SBC-FRAUD-ERROR` is logged.
7. Active call + `scamstop fraud quarantine <id>` → ScamStop ends it within one poll +
   `confirm_delays_s`; `sbc:fraud:v1:ack:<Call-ID>` shows `termination_confirmed`; both legs get BYE.
8. `dlg_end_dlg` on a dialog the switch refuses to end (e.g. MI stub) → `failed` after retries.
9. Run the portal sync (`sbc-portal-sync.sh`) while deny records exist → records unchanged.
10. Exact MI reply for `dlg_list callid=<unknown>` (empty list vs. error) — ScamStop accepts both.

## 12. Migration

Order matters: each step is safe on its own and can be stopped at.

1. **ScamStop, advisory.** Deploy this version with `carrier.enabled: true`,
   `carrier.policy.enforce: false`, `carrier.escalation.enabled: false`. Confirm the panel
   shows `policy: carrier`, coverage `complete`, and that `scamstop_attribution_untrusted`
   grows (the switch doesn't send values yet). Nothing is written to `sbc:cust:*`.
2. **Portal:** add the 8th `reseller_id` field (§8.1). Old switch config ignores it.
3. **Switch, attribution only:** add fragments 1 and 3 from `opensips-fraud-gate.cfg`
   (the `$var(fa_*)` resets and the `$dlg_val(fa_*)` block), not `route(FRAUD_GATE)`.
   Check `dlg_list_ctx`; `scamstop_attribution_untrusted` should stop growing for registry calls.
4. **Review a week of logs** (`kills.jsonl`, `flags.jsonl`, `escalation.jsonl` with
   `scamstop eval` on labeled samples; docs/evaluation.md).
5. **ScamStop, enforcing:** `carrier.policy.enforce: true`; then `escalation.enabled: true`.
6. **Switch, deny gate:** add `route(FRAUD_GATE)` and its statistics.
7. **Portal:** read-only fraud view and requests stream (§8.2–3).

Existing `sbc:block:*` lists, strikes, evidence logs and the feed state carry over unchanged.

## 13. Rollback

Every step above is reversible independently:

* **ScamStop to advisory:** `carrier.policy.enforce: false` (restart). Calls are only logged.
* **ScamStop off carrier mode:** `carrier.enabled: false` and restart. Standalone behaviour
  returns; with `redis.customer_key` left at `sbc:cust:{ip}` it will treat registry keys as
  "monitored IPs" (read-only `EXISTS`). Do **not** re-enable `hosted.enabled` against the
  carrier's Redis: standalone tenant sync writes `sbc:cust:*`.
* **Previous ScamStop version:** reinstall the previous installer; it ignores `sbc:fraud:v1:*`.
  (Note: the previous version's hosted-tenant sync writes `sbc:cust:*`; keep `hosted.enabled: false`.)
* **Switch:** remove `route(FRAUD_GATE)` to stop denying new calls; remove the `$dlg_val(fa_*)`
  block to stop sending attribution. Both are additive and have no other effect.
* **Clear all fraud state** (only if PVN decides to): `scamstop fraud list`, then
  `scamstop fraud unblock <id> --case <case> --revision <rev>` per record, which keeps the
  audit trail. Deleting `sbc:fraud:v1:*` by hand loses the audit and is not recommended.
* **Portal 8th field:** harmless to keep; to remove, drop it from `buildRegistry` and the grep.
