"""8 kHz mu-law WAV -> pcap of RTP packets (PT 0, 20 ms) that SIPp's play_pcap_audio can replay."""
import struct, sys
src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
i = data.index(b"data") + 8           # skip to the raw mu-law samples
ulaw = data[i:]

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF

out = open(dst, "wb")
out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))   # pcap header, Ethernet
src_ip, dst_ip = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
t0, seq, ts = 1_700_000_000.0, 1000, 0
for n in range(0, len(ulaw) - 159, 160):
    rtp = struct.pack("!BBHII", 0x80, 0, seq & 0xFFFF, ts & 0xFFFFFFFF, 0x12345678) + ulaw[n:n + 160]
    udp = struct.pack("!HHHH", 6000, 6000, 8 + len(rtp), 0) + rtp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    eth = b"\x00" * 12 + b"\x08\x00"
    frame = eth + ip + udp
    t = t0 + seq * 0.02
    out.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(frame), len(frame)) + frame)
    seq += 1; ts += 160
out.close()
print(dst, (seq - 1000), "packets")
