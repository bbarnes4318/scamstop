"""Switch-resolved attribution (dlg_list_ctx dialog values), strictly validated."""
import pytest

from scamstop import attribution, config, control
from scamstop.control import Dialog

NAMES = config.load(None)["carrier"]["attribution"]["values"]


def dlg(values, callid="abc123@203.0.113.7", **kw):
    raw = {"values": [{k: v} for k, v in values.items()]} if values is not None else {}
    return Dialog(kw.get("id", "6ae.4b38d013"), callid, "ftag", kw.get("contact_host", "198.51.100.9"),
                  raw=raw, callee_tag="ttag")


def test_direct_customer():
    a = attribution.from_dialog(dlg({"fa_v": "1", "fa_cust": "1042", "fa_src": "203.0.113.10",
                                     "fa_entry": "91.98.108.76"}), NAMES)
    assert a.trusted and a.customer_id == "1042" and a.parent_id is None and a.account == "1042"
    assert a.dialog_id == "6ae.4b38d013" and a.from_tag == "ftag" and a.to_tag == "ttag"


def test_reseller_child_is_the_account_not_the_reseller():
    a = attribution.from_dialog(dlg({"fa_v": "1", "fa_cust": "2077", "fa_parent": "1500",
                                     "fa_ep": "pfx:1500:101", "fa_src": "203.0.113.20"}), NAMES)
    assert a.trusted and a.customer_id == "2077" and a.parent_id == "1500" and a.endpoint == "pfx:1500:101"


def test_contact_host_and_callid_host_never_become_identity():
    a = attribution.from_dialog(dlg(None, callid="x@74.81.33.58", contact_host="203.0.113.10"), NAMES)
    assert not a.trusted and a.customer_id is None and a.problem == "no_values"


@pytest.mark.parametrize("values,problem", [
    ({"fa_v": "2", "fa_cust": "1"}, "bad_version"),
    ({"fa_cust": "1"}, "bad_version"),
    ({"fa_v": "1", "fa_cust": ""}, "bad_customer_id"),
    ({"fa_v": "1", "fa_cust": "0"}, "bad_customer_id"),
    ({"fa_v": "1", "fa_cust": "12 34"}, "bad_customer_id"),
    ({"fa_v": "1", "fa_cust": "1;DEL sbc:cust:*"}, "bad_customer_id"),
    ({"fa_v": "1", "fa_cust": "1" * 19}, "bad_customer_id"),
    ({"fa_v": "1", "fa_cust": "203.0.113.10"}, "bad_customer_id"),   # a fallback source-IP key is not an id
    ({"fa_v": "1", "fa_cust": "5", "fa_parent": "5"}, "bad_parent_id"),
    ({"fa_v": "1", "fa_cust": "5", "fa_parent": "x"}, "bad_parent_id"),
    ({"fa_v": "1", "fa_cust": "5", "fa_src": "999.1.1.1"}, "bad_src_ip"),
    ({"fa_v": "1", "fa_cust": "5", "fa_entry": "::1"}, "bad_entry_ip"),
    ({"fa_v": "1", "fa_cust": "5", "fa_ep": "pfx:1:12"}, "bad_endpoint"),
    ({"fa_v": "1", "fa_cust": "5", "fa_ep": "pfx:9:101"}, "endpoint_parent_mismatch"),
    ({"fa_v": "1", "fa_cust": "5", "fa_parent": "8", "fa_ep": "pfx:9:101"}, "endpoint_parent_mismatch"),
])
def test_invalid_values_are_untrusted(values, problem):
    a = attribution.from_dialog(dlg(values), NAMES)
    assert not a.trusted and a.problem == problem and a.account is None


def test_bad_callid_rejected():
    assert attribution.from_dialog(dlg({"fa_v": "1", "fa_cust": "5"}, callid="a b"), NAMES).problem == "bad_callid"
    assert attribution.from_dialog(dlg({"fa_v": "1", "fa_cust": "5"}, callid="x" * 300), NAMES).problem == "bad_callid"


def test_values_as_object_or_nested_context():
    d = Dialog("1", "c@h", "t", "", raw={"context": {"values": {"fa_v": "1", "fa_cust": "77"}}})
    assert attribution.from_dialog(d, NAMES).customer_id == "77"
    d = Dialog("1", "c@h", "t", "", raw={"values": [{"fa_v": True}, {"fa_cust": ["x"]}]})
    assert not attribution.from_dialog(d, NAMES).trusted


class FakeMI(control.OpenSIPS):
    def __init__(self, reply):
        super().__init__(url="http://unused", with_context=True)
        self.reply, self.calls = reply, []

    def _call(self, method, params=None):
        self.calls.append((method, params))
        return self.reply(method, params)


def test_opensips_lists_with_context_and_checks_one_dialog():
    rec = {"ID": "6ae.1", "state": 4, "callid": "c1@x", "caller_tag": "a", "callee_tag": "b",
           "caller_contact": "sip:1@198.51.100.9", "values": [{"fa_v": "1"}, {"fa_cust": "42"}]}
    mi = FakeMI(lambda m, p: {"Dialogs": [rec] if m != "dlg_list" or p.get("callid") == "c1@x" else []})
    [d] = mi.list_all()
    assert mi.calls[0][0] == "dlg_list_ctx"
    assert attribution.from_dialog(d, NAMES).customer_id == "42"
    assert mi.exists(d) is True
    mi.reply = lambda m, p: {"Dialogs": []}
    assert mi.exists(d) is False
    mi.reply = lambda m, p: {"Dialogs": [dict(rec, ID="6ae.2")]}   # same Call-ID, another dialog
    assert mi.exists(d) is False


def test_platform_reads_context_only_in_carrier_mode():
    from scamstop.platforms.sip import SipPlatform
    c = config.load(None)
    c["proxy"].update(type="opensips", url="http://127.0.0.1:1/mi")
    assert SipPlatform.from_config(c).proxy.with_context is False
    c["carrier"]["enabled"] = True
    assert SipPlatform.from_config(c).proxy.with_context is True
