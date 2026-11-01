# Evaluating ScamStop

## What the bundled numbers are (and are not)

`tests/data/smart_heldout.txt` (60 hand-written snippets) and
`tests/data/regression_pairs.yaml` (legitimate/scam pairs) are **regression fixtures**. They
catch rule and model regressions in CI. They are small, written by the developers, and not
drawn from real traffic, so they say nothing reliable about precision or recall on PVN's calls.
Do not quote them as accuracy.

## Reporting at the real thresholds

```bash
scamstop eval tests/data/smart_heldout.txt            # labeled transcripts
scamstop eval --pairs tests/data/regression_pairs.yaml
scamstop eval calls.jsonl --rows                       # your own labeled set, per-call verdicts
```

The report keeps layers apart, each at the thresholds in your config:

| Section | What it measures |
|---|---|
| `phrase.kill` / `phrase.flag_or_kill` | caller + victim rule packs, with cross-side corroboration, as the daemon runs them |
| `smart.flag@<threshold>` / `smart.kill@<kill_threshold>` | the smart classifier **as the live check runs it**: sliding windows, nothing scored before `min_words`; `too_short_to_score` counts calls it would never score |
| `smart_ungated.*` | the classifier alone on each whole transcript (what `smart-eval` reports) |
| `combined.flag_or_kill` | anything either layer would surface |
| `combined.kill` | what actually ends calls with the current config: phrase kills, plus smart kills only when `smart.mode: kill` |

On the bundled 60-snippet fixture (Nov 2026, default config) the live-gated smart check scores
only 6 of 60 snippets because 54 are shorter than `min_words: 25`. That is a property of the
fixture (short snippets), and exactly why a real-call evaluation is needed.

## A representative, labeled real-call evaluation (no production recordings accessed by developers)

The goal is precision and recall on PVN's actual traffic mix, measured by people authorised to
handle call content, under PVN's legal basis (see LEGAL.md). Developers receive only aggregate
metrics and, optionally, de-identified transcripts approved for release.

1. **Sample, don't cherry-pick.** Draw calls uniformly at random per customer (stratified by
   customer and by hour of day) from the period under review, plus *all* calls ScamStop killed
   or flagged in the period. Keep the two strata separate: the random stratum estimates
   prevalence and recall; the flagged stratum estimates precision. Record sampling weights.
2. **Transcribe with the production pipeline**, on PVN infrastructure: `scamstop scan-audio` on
   recordings PVN already lawfully holds, or the `evidence.watch_regex` transcripts for a
   consented test window. Store caller and called-party sides separately (`caller`, `victim`).
3. **Label blind.** Two trained PVN reviewers label each call scam / not-scam / unsure without
   seeing ScamStop's verdict, following a written guide (impersonation, payment demands,
   coercion, secrecy coaching ⇒ scam; legitimate sales, intake, support, reminders ⇒ not).
   Resolve disagreements with a third reviewer; report inter-rater agreement (Cohen's κ).
   Drop or report "unsure" separately; never fold it into either class.
4. **Export JSONL** — `{"id", "label", "caller", "victim", "customer_id", "stratum", "weight"}` —
   de-identified (strip names, numbers, addresses) before it leaves the restricted environment.
5. **Run** `scamstop eval calls.jsonl --rows` with the production config. Report, per layer and
   combined: precision and recall at the flag and kill thresholds with 95% confidence intervals
   (Wilson), weighted by stratum; false positives broken down by customer and rule; and
   recall broken down by scam type.
6. **Gate changes on it.** Before enabling `smart.mode: kill`, require kill-threshold precision
   with a lower confidence bound ≥ the target (e.g. 0.99) on at least a few hundred kills;
   before turning a context rule into a strong one, require zero false kills in its stratum.
7. **Repeat** quarterly and after any rule-pack or model change; keep each labeled set frozen
   and versioned so results are comparable.

The panel's "Yes, correct / Not a scam" buttons (labels.jsonl) are useful feedback but are a
biased sample (only flagged calls, reviewed by whoever looked); they measure precision of flags,
not recall, and should not replace the process above.

## Capacity

ScamStop does not ship a capacity claim. `monitor.max_streams` is a configured limit, not a
measurement. To size it for a server:

1. Replay a representative mix of recorded calls through the lab SBC with SIPp (`tests/e2e/`)
   at increasing concurrency, with the production config (both sides, smart check, LLM on/off).
2. Watch `scamstop_queue_delay_seconds_max`, `scamstop_dropped_chunks`, `scamstop_cpu_seconds`
   and the coverage status. The sustainable concurrency is the highest step where queue delay
   stays under `monitor.queue_delay_warn_s` and nothing is dropped for the whole step.
3. Set `max_streams` below that, and pick `monitor.overload`: `skip_new` (refuse new calls
   past the limit) or `shed_victim` (drop called-party listening first to keep caller coverage).

Whatever the limit, overload is visible: skipped calls (`scamstop_skipped_cap`), shed victim
sides (`scamstop_victim_shed`), dropped audio, queue delay, listener failures and unconfirmed
terminations all turn the status from `complete` to `degraded` for `monitor.coverage_window_s`.
