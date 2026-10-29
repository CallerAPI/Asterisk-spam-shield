import io
import json
import sys
import unittest
import urllib.error
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import spam_shield

# Ofcom drama range. This is not a live subscriber number.
OFCOM = "+447700900123"
PAI_HEADER = "PJSIP_HEADER(read,P-Asserted-Identity)"


class AgiSession:
    """Minimal AGI peer for one script run."""

    def __init__(self, env, variables):
        self.variables = dict(variables)
        self.commands = []
        self.assigned = {}
        self._responses = []
        self._env = ["%s: %s\n" % (key, value) for key, value in env.items()]
        self._env.append("\n")
        self.stdin = _Stdin(self)
        self.stdout = _Stdout(self)

    def readline(self):
        if self._env:
            return self._env.pop(0)
        if not self._responses:
            return ""
        return self._responses.pop(0)

    def write(self, data):
        if not data.endswith("\n"):
            raise AssertionError("partial AGI write: %r" % data)
        command = data[:-1]
        self.commands.append(command)
        if command.startswith("GET VARIABLE "):
            name = command[len("GET VARIABLE "):]
            value = self.variables.get(name, "")
            if value == "":
                self._responses.append("200 result=0\n")
            else:
                self._responses.append("200 result=1 (%s)\n" % value)
            return
        if command.startswith("SET VARIABLE "):
            key, raw = _parse_set(command)
            self.assigned[key] = raw
            self._responses.append("200 result=1\n")
            return
        self._responses.append("510 Invalid or unknown command\n")


class _Stdin:
    def __init__(self, session):
        self._session = session

    def readline(self):
        return self._session.readline()


class _Stdout:
    def __init__(self, session):
        self._session = session

    def write(self, data):
        self._session.write(data)

    def flush(self):
        return None


class _Body:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _parse_set(command):
    rest = command[len("SET VARIABLE "):]
    key, quoted = rest.split(" ", 1)
    inner = quoted[1:-1]
    inner = inner.replace('\\"', '"').replace("\\\\", "\\")
    return key, inner


def _opener(sink, payload=None, error=None):
    def urlopen(req, timeout=1.5):
        sink.append((req, timeout))
        if error is not None:
            raise error
        body = payload or {
            "data": {
                "is_spam": False,
                "spam_score": 0,
                "reputation": "UNKNOWN",
                "total_complaints": 0,
                "entity_type": "UNKNOWN",
                "business_info": {},
            }
        }
        return _Body(body)

    return urlopen


def _run(env, variables=None, opener=None, environ=None):
    session = AgiSession(env, variables or {})
    calls = []
    spam_shield.run(
        session.stdin,
        session.stdout,
        urlopen=opener or _opener(calls),
        environ={} if environ is None else environ,
    )
    return session, calls


def _assert_skipped(test, session, calls, read_pai=False):
    test.assertEqual(calls, [])
    test.assertEqual(session.assigned["CA_LOOKUP_STATUS"], "skip:withheld")
    test.assertEqual(session.assigned["CA_IS_SPAM"], "0")
    test.assertEqual(session.assigned["CA_REPUTATION"], "UNKNOWN")
    test.assertNotIn("fail:no_caller", session.assigned.values())
    if not read_pai:
        test.assertNotIn(PAI_HEADER, "\n".join(session.commands))


class DecisionTests(unittest.TestCase):
    def test_restricted_names_and_numbers(self):
        for value in (
            "prohib",
            "Prohib",
            "prohib_not_screened",
            "prohib_passed_screen",
            "prohib_failed_screen",
            "restricted",
            "32",
            "33",
            "34",
            "35",
        ):
            self.assertTrue(spam_shield.is_restricted_presentation(value), value)
        for value in ("", "allowed", "allowed_not_screened", "0", "1", "64", "unavailable"):
            self.assertFalse(spam_shield.is_restricted_presentation(value), value)

    def test_phone_number_rejects_withheld_text(self):
        self.assertFalse(spam_shield.is_phone_number(""))
        self.assertFalse(spam_shield.is_phone_number("   "))
        self.assertFalse(spam_shield.is_phone_number("anonymous"))
        self.assertFalse(spam_shield.is_phone_number("Unknown"))
        self.assertFalse(spam_shield.is_phone_number("restricted"))
        self.assertFalse(spam_shield.is_phone_number("<anonymous>"))
        self.assertTrue(spam_shield.is_phone_number(OFCOM))
        self.assertTrue(spam_shield.is_phone_number("5550100"))

    def test_extract_e164_uses_uri_not_display_name(self):
        header = '"Desk +447700900456" <sip:anonymous@gateway.example>'
        self.assertIsNone(spam_shield.extract_e164(header))
        sip = '"Network" <sip:%s@gateway.example>' % OFCOM
        self.assertEqual(spam_shield.extract_e164(sip), OFCOM)
        self.assertEqual(spam_shield.extract_e164("tel:%s" % OFCOM), OFCOM)
        self.assertEqual(spam_shield.extract_e164(OFCOM), OFCOM)
        self.assertIsNone(spam_shield.extract_e164("sip:447700900123@gateway.example"))
        self.assertIsNone(spam_shield.extract_e164("tel:+123"))

    def test_pai_flag_defaults_off_and_argument_wins(self):
        self.assertFalse(spam_shield.pai_lookup_enabled({}, {}))
        self.assertFalse(spam_shield.pai_lookup_enabled({}, {"CALLERAPI_WITHHELD_PAI": "0"}))
        self.assertTrue(
            spam_shield.pai_lookup_enabled({}, {"CALLERAPI_WITHHELD_PAI": "1"})
        )
        self.assertTrue(
            spam_shield.pai_lookup_enabled({"agi_arg_2": "yes"}, {})
        )
        self.assertFalse(
            spam_shield.pai_lookup_enabled(
                {"agi_arg_2": "0"},
                {"CALLERAPI_WITHHELD_PAI": "1"},
            )
        )


class WithheldLookupTests(unittest.TestCase):
    def test_empty_caller_skips_lookup(self):
        session, calls = _run({"agi_callerid": "", "agi_arg_1": "test-key"})
        _assert_skipped(self, session, calls)

    def test_missing_caller_skips_lookup(self):
        session, calls = _run({"agi_arg_1": "test-key"})
        _assert_skipped(self, session, calls)

    def test_anonymous_caller_skips_lookup(self):
        session, calls = _run({"agi_callerid": "anonymous", "agi_arg_1": "test-key"})
        _assert_skipped(self, session, calls)

    def test_unknown_caller_skips_lookup(self):
        session, calls = _run({"agi_callerid": "unknown", "agi_arg_1": "test-key"})
        _assert_skipped(self, session, calls)

    def test_restricted_text_skips_lookup(self):
        session, calls = _run({"agi_callerid": "restricted", "agi_arg_1": "test-key"})
        _assert_skipped(self, session, calls)

    def test_restricted_presentation_skips_lookup(self):
        session, calls = _run(
            {
                "agi_callerid": OFCOM,
                "agi_callingpres": "0",
                "agi_arg_1": "test-key",
            },
            {
                "CALLERID(num-pres)": "prohib",
                "CALLERPRES()": "prohib_passed_screen",
            },
        )
        _assert_skipped(self, session, calls)
        self.assertIn("GET VARIABLE CALLERID(num-pres)", session.commands)
        self.assertIn("GET VARIABLE CALLERPRES()", session.commands)
        self.assertNotIn(OFCOM, "\n".join(session.commands))

    def test_callingpres_restricted_bit_skips_lookup(self):
        session, calls = _run(
            {
                "agi_callerid": OFCOM,
                "agi_callingpres": "32",
                "agi_arg_1": "test-key",
            },
            {
                "CALLERID(num-pres)": "allowed_not_screened",
                "CALLERPRES()": "allowed_not_screened",
            },
        )
        self.assertEqual(calls, [])
        self.assertEqual(session.assigned["CA_LOOKUP_STATUS"], "skip:withheld")

    def test_pai_opt_in_looks_up_e164_without_exposing_it(self):
        calls = []
        payload = {
            "data": {
                "is_spam": True,
                "spam_score": 40,
                "reputation": "BAD",
                "total_complaints": 2,
                "entity_type": "PERSON",
                "business_info": {
                    "verified": False,
                    "business_name": "",
                    "category": "",
                    "industry": "",
                },
            }
        }
        session, _ = _run(
            {"agi_callerid": "anonymous", "agi_arg_1": "test-key"},
            {PAI_HEADER: '"Network" <sip:%s@gateway.example>' % OFCOM},
            opener=_opener(calls, payload),
            environ={"CALLERAPI_WITHHELD_PAI": "1"},
        )
        self.assertEqual(len(calls), 1)
        req, timeout = calls[0]
        self.assertEqual(timeout, 1.5)
        self.assertEqual(
            req.full_url,
            "https://callerapi.com/api/lookup/%s" % urllib.parse.quote(OFCOM, safe=""),
        )
        self.assertEqual(req.get_header("X-auth"), "test-key")
        self.assertEqual(req.get_header("User-agent"), "Asterisk-CallerAPI/1.0")
        self.assertIn("GET VARIABLE %s" % PAI_HEADER, session.commands)
        self.assertEqual(session.assigned["CA_LOOKUP_STATUS"], "ok")
        self.assertEqual(session.assigned["CA_IS_SPAM"], "1")
        self.assertEqual(session.assigned["CA_SPAM_SCORE"], "40")
        self.assertEqual(session.assigned["CA_REPUTATION"], "BAD")
        self.assertNotIn(OFCOM, "\n".join(session.commands))
        for value in session.assigned.values():
            self.assertNotIn("447700900123", value)
        self.assertFalse(any(command.startswith("SET CALLERID") for command in session.commands))

    def test_pai_argument_enables_lookup(self):
        calls = []
        session, _ = _run(
            {
                "agi_callerid": "unknown",
                "agi_arg_1": "test-key",
                "agi_arg_2": "1",
            },
            {PAI_HEADER: "tel:%s" % OFCOM},
            opener=_opener(calls),
            environ={},
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(session.assigned["CA_LOOKUP_STATUS"], "ok")
        self.assertNotIn("447700900123", "\n".join(session.commands))

    def test_pai_stays_off_by_default(self):
        session, calls = _run(
            {"agi_callerid": "anonymous", "agi_arg_1": "test-key"},
            {PAI_HEADER: "tel:%s" % OFCOM},
            environ={},
        )
        _assert_skipped(self, session, calls)

    def test_pai_without_e164_skips_lookup(self):
        session, calls = _run(
            {"agi_callerid": "anonymous", "agi_arg_1": "test-key", "agi_arg_2": "on"},
            {PAI_HEADER: '"Desk +447700900456" <sip:anonymous@gateway.example>'},
            environ={},
        )
        _assert_skipped(self, session, calls, read_pai=True)
        self.assertIn("GET VARIABLE %s" % PAI_HEADER, session.commands)

    def test_pai_result_hides_echoed_number(self):
        calls = []
        payload = {
            "data": {
                "is_spam": False,
                "spam_score": 3,
                "reputation": "NEUTRAL",
                "total_complaints": 0,
                "entity_type": "BUSINESS",
                "business_info": {
                    "verified": True,
                    "business_name": "Desk %s" % OFCOM,
                    "category": "office",
                    "industry": "comms",
                },
            }
        }
        session, _ = _run(
            {"agi_callerid": "anonymous", "agi_arg_1": "test-key", "agi_arg_2": "1"},
            {PAI_HEADER: "tel:%s" % OFCOM},
            opener=_opener(calls, payload),
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(session.assigned["CA_LOOKUP_STATUS"], "ok")
        self.assertEqual(session.assigned["CA_BIZ_VERIFIED"], "1")
        self.assertEqual(session.assigned["CA_BIZ_NAME"], "")
        self.assertEqual(session.assigned["CA_BIZ_CATEGORY"], "office")
        self.assertEqual(session.assigned["CA_REPUTATION"], "NEUTRAL")
        self.assertNotIn("447700900123", "\n".join(session.commands))

    def test_allowed_number_still_looks_up(self):
        calls = []
        session, _ = _run(
            {"agi_callerid": OFCOM, "agi_callingpres": "0", "agi_arg_1": "test-key"},
            {
                "CALLERID(num-pres)": "allowed_not_screened",
                "CALLERPRES()": "allowed",
            },
            opener=_opener(calls),
        )
        self.assertEqual(len(calls), 1)
        req, timeout = calls[0]
        self.assertEqual(timeout, 1.5)
        self.assertEqual(
            req.full_url,
            "https://callerapi.com/api/lookup/%s" % urllib.parse.quote(OFCOM, safe=""),
        )
        self.assertEqual(session.assigned["CA_LOOKUP_STATUS"], "ok")
        self.assertNotIn(PAI_HEADER, "\n".join(session.commands))

    def test_lookup_error_keeps_failure_status(self):
        calls = []
        error = urllib.error.HTTPError(
            "https://callerapi.com/api/lookup/5550100",
            401,
            "denied",
            hdrs=None,
            fp=io.BytesIO(b""),
        )
        session, _ = _run(
            {"agi_callerid": "5550100", "agi_arg_1": "test-key"},
            {
                "CALLERID(num-pres)": "allowed_not_screened",
                "CALLERPRES()": "allowed",
            },
            opener=_opener(calls, error=error),
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(session.assigned["CA_LOOKUP_STATUS"], "fail:HTTPError")
        self.assertNotIn("447700900123", session.assigned["CA_LOOKUP_STATUS"])


if __name__ == "__main__":
    unittest.main()
