# Contributing

The rules are the product. Every new scam script someone writes a rule for protects every carrier that runs ScamStop.

## Adding or changing a rule

1. Edit `scamstop/rules/en_scams.yaml`, or add a new pack such as `es_scams.yaml`.
2. Match **phrases a legitimate caller would never say**. Single words like "medicare", "refund", "bank" or "warrant" are not enough.
3. Add at least one `examples.hit` taken from a real scam call (anonymized), and at least one `examples.miss` showing the closest legitimate sentence you can think of.
4. Use `action: flag` if a real business could plausibly say it.
5. Run `pytest` and `scamstop test-rules`. Both must pass.
6. In the pull request, say how many real transcripts you tested against and the hit and false-positive counts (for example "212/242 scam calls, 0/1968 others").

**Never commit real phone numbers, names or full transcripts of real victims.** Paraphrase the scam's wording into the example.

## New languages

A new language needs a streaming sherpa-onnx model for that language (set `asr.model_dir`) and a rule pack written against that model's output. Run one ScamStop instance per language model, or open an issue to discuss language routing.

## New proxies

Implement `list_answered()` and `end()` in `scamstop/control.py`, returning `Dialog` objects. FreeSWITCH and Asterisk adapters are welcome. They would fork audio with their own mechanisms (mod_audio_fork, ExternalMedia) instead of rtpengine.
