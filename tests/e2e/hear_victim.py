import struct, sys, numpy as np
sys.path.insert(0, "/home/claude/scamstop")
from scamstop import audio
from scamstop.asr import make_recognizer
data = open("/tmp/e2e2/victim.pcap", "rb").read()
i, pk = 24, []
while i + 16 <= len(data):
    ts, us, incl, _ = struct.unpack("<IIII", data[i:i+16]); frame = data[i+16:i+16+incl]; i += 16 + incl
    p = audio.rtp_payload(frame[14+20+8:])
    if p and p[0] == 0: pk.append((ts + us/1e6, p[1]))
t0 = pk[0][0]
print(f"packets to the person called: {len(pk)} over {pk[-1][0]-t0:.1f}s")
rec = make_recognizer("/opt/scamstop/models/sherpa-onnx-streaming-zipformer-en-2023-06-21")
def hear(a, b):
    pcm = np.concatenate([audio.decode_g711(x, 0) for t, x in pk if a <= t - t0 < b])
    s = rec.create_stream(); s.accept_waveform(16000, (audio.upsample_8k_16k(pcm) / 32768).astype(np.float32))
    s.accept_waveform(16000, np.zeros(16000, np.float32)); s.input_finished()
    out = []
    while rec.is_ready(s):
        rec.decode_stream(s)
        if rec.is_endpoint(s): out.append(rec.get_result(s)); rec.reset(s)
    out.append(rec.get_result(s)); return " ".join(out).lower().strip()
print("before detection:", hear(0, 9))
print("after detection: ", hear(10, 26))
