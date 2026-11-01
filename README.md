# ScamStop

**Scam-call protection as a hosted service: companies send their calls through your SBC, nothing to install.**

ScamStop listens to calls passing through your SBC and transcribes them on your own servers, with no cloud and no per-minute fees. When someone says something only a scammer says ("buy Google Play cards", "there's a warrant for your arrest", "Grandma, it's me, I got arrested"), the scammer is silenced, the person being called hears a warning, and the call ends. Repeat offenders are blocked, and the shared feed blocks them on every other network running ScamStop too.

## For the companies you protect

They never download or install anything:

1. **Sign up** in the portal: company name, email, password.
2. **Connect:** add the IPs their dialer sends from, then choose where calls go after checking, either your termination or their own carrier.
3. **Point their dialer at your SBC:** change one host field in ViciDial, FreePBX or any dialer. The portal shows them exactly where.
4. You **approve** the account, and their calls are protected from the next one.

Their portal shows scams stopped, calls flagged, a live feed with what was said, and their own protection settings: watch-only, warn then hang up, warn only, or hang up right away. (In carrier integration mode these settings belong to the carrier and are locked.)

## For you (the operator)

Run once on your own infrastructure:

1. **The SBC:** `deploy/sbc/opensips-scamstop-sbc.cfg` (OpenSIPS 3.2+) or `deploy/sbc/kamailio-scamstop-sbc.cfg` (Kamailio 5.6+), plus rtpengine 11+ and Redis. It accepts calls only from approved companies' IPs, rejects blocked sources before they ring, anchors media in rtpengine and relays each company's calls to its chosen carrier.
2. **ScamStop on the SBC server:** `sudo sh scamstop-installer-<version>-linux-x86_64.run`. Then in the admin console: **Companies → Hosted service**, set your SBC address and optional termination, and turn the hosted service on (`hosted.enabled: true`).
3. Share the portal address. New sign-ups appear under **Companies** for approval.

Verified end to end with real SIP calls (SIPp dialer → Kamailio SBC + rtpengine → SIPp carrier). A scam script was caught in about 10 seconds, the called party heard only the warning, and a legitimate Medicare call went through untouched. See `tests/e2e/`.

## Carrier integration mode (PVN)

For a carrier that already runs its own SBC and customer portal, ScamStop runs in **carrier
integration mode** (`carrier.enabled: true`) instead of the hosted SBC above:

- the carrier's switch resolves who each call belongs to (customer, reseller, source and entry
  IP, prefix) and stores it on the dialog; ScamStop reads that, never the SIP Contact or Call-ID;
- the carrier's portal stays authoritative for the customer registry (`sbc:cust:*`,
  `sbc:entry:*`), which ScamStop never writes;
- the carrier's mandatory policy wins: customers cannot switch protection off from any API or UI;
- customer-level blocks live in their own namespace, `sbc:fraud:v1:deny:customer:<id>`, which
  portal syncs never clear; accounts are quarantined only on strong, corroborated evidence, and
  a reseller's offending child is quarantined, not the reseller;
- hang-ups are verified (`termination_confirmed` / `failed` / `unknown`), and active calls are
  re-checked when a block changes.

The contract between the switch, the portal and ScamStop, with migration and rollback steps, is
[docs/carrier-integration-v1.md](docs/carrier-integration-v1.md). Switch-side reference
fragments: `deploy/carrier/opensips-fraud-gate.cfg`.

## Installing ScamStop on your SBC server

```bash
sudo sh scamstop-installer-0.6.0-linux-x86_64.run
```

The installer is one self-contained file. Python, every library and the speech model are inside it, so it fetches nothing except your distribution's own Redis package. It works on Debian, Ubuntu, RHEL/Alma/Rocky, Fedora and openSUSE, on any 64-bit Intel/AMD server with glibc 2.17 or newer. It:
- detects the phone system on the server and fills in its settings;
- starts the admin console over HTTPS and prints its address and password;
- starts in watch-only mode.

To build the installer: `packaging/build-installer.sh` writes `dist/scamstop-installer-<version>-linux-x86_64.run`.

## Running on a company's own switch

ScamStop can also run directly on a company's own phone system instead of behind your SBC:

| Phone system | How ScamStop connects | What you change on it |
|---|---|---|
| **OpenSIPS 3.x** + rtpengine 11+ | dialog module over the MI FIFO or mi_http; audio forked by rtpengine | nothing (the dialog and mi_fifo modules must be loaded) |
| **Kamailio 5.x** + rtpengine 11+ | dialog module over JSON-RPC; audio forked by rtpengine | nothing (dialog + jsonrpcs must be loaded) |
| **Asterisk 16.6+**: ViciDial, ViciBox, FreePBX, Issabel | stock ARI: a spy channel + External Media for audio, a whisper channel for the warning | ARI turned on. The panel does it in one click, with backups |
| **FreeSWITCH**: FusionPBX and others | stock event socket: a stereo recording to RAM for audio, `uuid_broadcast` for the warning | nothing |

The **System check** page confirms everything ScamStop needs (modules, versions, ports, Redis, the speech model, CPU) and gives the exact fix for anything missing.

## No changes to your switch

ScamStop ends calls from blocked call centers, spoofed caller IDs and do-not-call numbers by itself:
- **Asterisk and FreeSWITCH:** even while the call is still ringing.
- **OpenSIPS and Kamailio:** the moment the call connects.

For SIP proxies there's an optional snippet (shown in Setup) that rejects blocked calls before they ring.

## What happens when it hears a scam

Choose in Setup:

- **Warn, then hang up** (default). The person being called hears: *"Warning. This call shows signs of a scam. Do not buy gift cards, send money, or share any account numbers. Hang up now, and call your bank or your family directly, using a number you already know."* Then the call ends.
- **Warn only.** The person hears the warning and the call continues.
- **Hang up right away.** No warning.

A built-in recording ships with ScamStop, and you can upload your own in the panel. If the warning can't play, ScamStop hangs up instead, so a scam call is never left running.

Calls from the same center add up as strikes. After two killed calls (configurable), the center is blocked for 7 days. On Asterisk and FreeSWITCH, where there's no center IP, the caller ID gets the strikes instead. Blocks expire on their own, and ScamStop never blocks one of your own customers' IPs. Center strikes are supporting indicators only: suspending a customer account is a separate, stricter decision (carrier mode).

A hang-up request is not treated as proof that the call ended: ScamStop checks that the switch no longer lists the call, retries, and records `termination_confirmed`, `failed` or `unknown` for each call (`enforcement.jsonl`, panel, metrics).

## Listening to both sides

ScamStop also transcribes the **person being called**. Victims give scams away even when the script is careful or the scammer's accent defeats the speech model:
- "wait, you want me to buy Google Play cards?"
- "I'm at the Bitcoin machine now"
- "how much is the bail?"
- reading a long card number aloud (flag only, because real payments happen on sales calls)

A hit on either side warns, hangs up and strikes once. It's a switch in Setup; it roughly doubles CPU use.

## Smart check

Phrase rules catch exact scripts. The smart check catches reworded ones: a small model on your own server scores the last ~30 seconds of each call for scam intent.

- **Built in:** 67 KB, needs no GPU or downloads. Its bundled test set is 60 hand-written snippets: a regression fixture, not evidence of accuracy on real calls. Measure on your own labeled calls with `scamstop eval` ([docs/evaluation.md](docs/evaluation.md)), which reports the phrase rules, the smart check and both combined at your actual flag and kill thresholds.
- **Continuous:** a call is re-scored as it goes (bounded per call), so stronger evidence later in the call can still escalate a flag; each call gets at most one flag and one kill notification.
- **Optional second opinion:** any OpenAI-compatible model server you run, such as Ollama, llama.cpp or vLLM. Only calls that already look suspicious are sent, and nothing leaves your network. Requests are bounded (`max_concurrent`, `max_outstanding`, `max_per_call`), replies are strictly type-checked, both speakers are labelled, and a late verdict for a call that already ended is dropped.

**It starts out flag-only.** Every flag in the dashboard has **Yes, correct** and **Not a scam** buttons. **Hang up** stays locked until you've reviewed 50 flags and at least 95% were right. Your reviews also retrain it: `scamstop smart-train --labels /var/lib/scamstop/labels.jsonl`.

## Shared threat feed

Turn on **Shared feed** in the panel. Each network:
- **shares** the call centers and spoofed caller IDs it blocks, and withdraws them when it unblocks;
- **blocks** what the others caught, with blocks that expire on their own.

**Never shared:** transcripts, called numbers, customer IPs, do-not-call numbers, private IPs.

**Abuse resistance:** nothing is published until two different networks report it (or one trusted network does). Every network has a daily reporting quota, and the feed operator can ban a network, which pulls everything it reported.

Host a feed with `scamstop feed-server` (`deploy/systemd/scamstop-feed.service`). Its home page shows live public counters.

## The panel

Everything happens in the browser, over HTTPS, protected by a password with brute-force lockout:

- **Dashboard:** protecting, watching only or offline; scams stopped; centers blocked; a live feed where you can read each call's transcript and review it.
- **Setup** and **System check.**
- **Scam rules:** set each rule to Off, Flag or Hang up, and test any sentence.
- **Blocked:** block lists with expiry dates.
- **Shared feed** and **Customers.**

Most changes apply live. The panel tells you when a restart is needed (for example after switching phone systems) and does the restart for you.

## Rules

Caller-side and victim-side rule packs live as YAML in `scamstop/rules/`. A rule is either **strong** (enough on its own: payment demands, threats, secrecy coaching, safe-account transfers) or **context** (only a flag: "hi grandma", "public defender", "Wells Fargo fraud department", "new Medicare card", remote-support tools). Two context signals listed together under `corroboration`, from either side of the call, become one kill. Warnings ("we will never ask you to buy gift cards") and described speech ("if anyone says there's a warrant for your arrest, hang up") don't trigger kills. Every rule carries example sentences it must catch and must not catch, `tests/data/regression_pairs.yaml` holds legitimate/scam pairs, and the tests enforce all of them. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Commands

```bash
scamstop syscheck                         # what's on this server and what's missing
scamstop ui --host 0.0.0.0 --tls auto     # the panel (the installer runs it as a service)
scamstop run                              # the daemon (the installer runs it as a service)
scamstop test-rules                       # every rule's examples must pass
scamstop scan transcripts.jsonl           # run rules over saved transcripts
scamstop scan-audio call.wav              # transcribe a recording and scan it
scamstop block media 198.51.100.7 --ttl 30d --reason "traceback 2026-11-02"
scamstop blocks | unblock KIND VALUE | sweep
scamstop smart-train --labels FILE        # retrain the smart check on your reviewed calls
scamstop smart-eval FILE                  # its precision and recall on labeled calls
scamstop eval FILE                        # phrase / smart / combined precision+recall at your thresholds
scamstop fraud list|show|audit|block|quarantine|unblock   # carrier mode: customer deny records
scamstop feed-server | feed-admin | feed-sync
```

Upgrade: run a newer installer the same way; your settings are kept. Uninstall: `sudo sh scamstop-installer-….run --uninstall` (keeps `/etc/scamstop` and logs).

## Limits

- Capacity depends on hardware and traffic; `monitor.max_streams` is a limit you set, not a measured capacity. Size it with a load test (docs/evaluation.md). When ScamStop is over its limit, drops audio, falls behind or can't confirm a hang-up, the status shows **degraded** rather than claiming full protection.
- English only for now. Other languages need a matching speech model and rule pack.
- Asterisk needs 16.6 or newer, because that's when External Media was added. Older ViciBox installs need an Asterisk upgrade.
- On OpenSIPS and Kamailio, the warning needs rtpengine built with transcoding. Without it, ScamStop hangs up without the warning.
- Scammers adapt, so the rules need upkeep. That's what the shared feed, the smart check and contributions are for.

## Legal

Listening to call content is regulated. **Read [LEGAL.md](LEGAL.md) before you turn on hang-ups.**

## License

MIT
