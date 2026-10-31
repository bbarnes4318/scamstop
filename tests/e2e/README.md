# End-to-end test with real SIP calls

Runs the hosted SBC (Kamailio + rtpengine + Redis) with ScamStop and places real
calls with SIPp: a dialer that speaks the audio in a pcap, and a carrier that answers.

Verified results (Kamailio 5.7, rtpengine 11.5, SIPp 3.7):

| Call | Result |
|---|---|
| From a company not yet approved | 403 at the SBC |
| Scam script ("officer ... Social Security Administration ... suspended") | caught at ~10 s; the called party hears only the warning (caller silenced); SBC ends the call at ~25 s |
| Legitimate Medicare agent | untouched, ends normally |
| From a blocked caller ID | `603 Network Blocked` before ringing, with `Reason: SIP;cause=603;text="v=analytics1;tel=+19045128487";location=LN` |

Setup used: test IPs on `lo` (10.10.10.1 SBC, .2 dialer, .3 carrier, .4 unapproved),
`deploy/sbc/kamailio-scamstop-sbc.cfg` with SBC_IP=10.10.10.1, rtpengine
`--interface=10.10.10.1 --listen-ng=127.0.0.1:22222`, companies created with
`scamstop.tenants.Tenants`, audio made 8 kHz mu-law and turned into RTP with
`wav2pcap.py`. In `uac.xml`, replace AUDIO with the pcap path. `hear_victim.py`
transcribes what the called party received (from a tcpdump of RTP to the carrier).
