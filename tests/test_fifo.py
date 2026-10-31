"""OpenSIPS mi_fifo client against a fake OpenSIPS reading a real FIFO."""
import json
import os
import threading

from scamstop.control import OpenSIPS


def fake_opensips(fifo, reply_dir, dialogs):
    with open(fifo) as f:
        line = f.readline()
    _, name, body = line.split(":", 2)
    req = json.loads(body)
    result = {"Dialogs": dialogs} if req["method"] == "dlg_list" else "OK"
    with open(os.path.join(reply_dir, name), "w") as r:
        r.write(json.dumps({"jsonrpc": "2.0", "result": result, "id": req["id"]}))


def test_fifo_list_answered(tmp_path):
    fifo = str(tmp_path / "opensips_fifo")
    os.mkfifo(fifo)
    dialogs = [{"ID": "1:2", "state": 4, "callid": "abc@1.2.3.4", "caller_tag": "t",
                "caller_contact": "sip:100@10.0.0.5:5060", "caller_bind_addr": "udp:1.1.1.1:5060"},
               {"ID": "3:4", "state": 2, "callid": "ringing"}]
    t = threading.Thread(target=fake_opensips, args=(fifo, str(tmp_path), dialogs))
    t.start()
    out = OpenSIPS(fifo=fifo, reply_dir=str(tmp_path)).list_answered()
    t.join(2)
    assert [d.callid for d in out] == ["abc@1.2.3.4"] and out[0].caller_ip == "10.0.0.5"
    assert not [p for p in os.listdir(tmp_path) if p.startswith("scamstop_")]  # reply fifo cleaned up


def test_fifo_missing(tmp_path):
    try:
        OpenSIPS(fifo=str(tmp_path / "nope")).list_answered()
    except FileNotFoundError as e:
        assert "mi_fifo" in str(e)
