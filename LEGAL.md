# Legal considerations for operators

This is not legal advice. ScamStop's authors are not your lawyers. Get advice from a telecom attorney in every jurisdiction where you run it.

## Listening to calls

ScamStop processes the audio content of calls passing through your network. Interception and wiretap laws apply in most places. Examples:

- **United States.** The federal Wiretap Act (18 U.S.C. § 2511) generally prohibits intercepting call content. It has a narrow exception for a provider monitoring "while engaged in any activity which is a necessary incident to the rendition of his service or to the protection of the rights or property of the provider." Whether real-time scam detection fits that exception is a question for your counsel. Some states, including California, Florida, Illinois, Maryland, Massachusetts, Pennsylvania and Washington, require every party's consent for recording and may treat transcription the same way.
- **EU and UK.** The ePrivacy Directive, GDPR and the UK's Investigatory Powers Act and PECR restrict access to communications content. You will likely need a documented legal basis and a data-protection impact assessment.
- **Elsewhere.** Check national telecom secrecy laws.

## Ways to reduce exposure

- **Contracts.** Require wholesale customers to accept content-based fraud monitoring in your service agreement and AUP, and to pass a notice down to their own call centers.
- **Keep only what you need.** Calls that aren't killed or flagged are never stored by default. Set `evidence.transcript: window` or `none` to keep less on kills. Set a retention period on `/var/log/scamstop/` (logrotate) and stick to it.
- **Leave the review and watch logs off** unless you have a specific, documented reason. Both store transcripts of calls that were not killed.
- **Run a dry-run period** first and record your false-positive rate.
- **Keep fraud protection separate from business rules.** The scam rules protect called parties and your network. The optional campaign gate (`campaigns.enabled`) hangs up legitimate-but-unwanted traffic. That is a business decision with a much weaker legal footing for content monitoring, and it is off by default.

## Warning messages

Playing a warning to the called party, instead of silently hanging up, is generally easier to defend. The person is told why, and nothing is decided for them. Keep the message factual, and don't name or accuse anyone. The built-in message is written that way.

## Shared threat feed

The feed exchanges IP addresses, hosted-dialer account tags and caller IDs, never call content. Under GDPR and similar laws, IP addresses and phone numbers can still be personal data. If you operate in those jurisdictions, document your legitimate interest (fraud prevention), keep the feed's retention short (`--ttl-days`), and honor removal requests with `scamstop feed-admin delete`. Feed operators should publish who runs the feed and how to request removal.

## Hanging up and blocking

Ending calls and blocking sources can breach your customer contracts if they're done wrongly. Spell out in your terms that calls matching fraud indicators may be terminated and their sources blocked, give customers an appeal path, and use expiring blocks (`centers.block_ttl_s`).

## Evidence

Kill records (time, rule, matched words, transcript, Call-ID, source, destination) are useful for traceback responses (for example the Industry Traceback Group in the US) and for your robocall-mitigation program. Handle them as sensitive personal data.
