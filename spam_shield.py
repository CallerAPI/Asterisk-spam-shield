#!/usr/bin/env python3
"""AGI script that checks caller reputation with CallerAPI.

The script skips the check when the caller ID is withheld.
An empty caller ID used to set fail:no_caller.
That case now sets skip:withheld.
The script still sends no request.
"""

import json
import os
import re
import sys
import urllib.parse
import urllib.request

PAI_ENV = "CALLERAPI_WITHHELD_PAI"
PAI_HEADER = "PJSIP_HEADER(read,P-Asserted-Identity)"
PRESENTATION_VARS = ("CALLERID(num-pres)", "CALLERPRES()")
LOOKUP_URL = "https://callerapi.com/api/lookup/%s"
USER_AGENT = "Asterisk-CallerAPI/1.0"
LOOKUP_TIMEOUT = 1.5

# Asterisk AST_PRES_RESTRICTED is 0x20. The restriction mask is 0x60.
_RESTRICTION_MASK = 0x60
_RESTRICTED_BIT = 0x20
_RESTRICTED_NAMES = {
    "prohib",
    "prohib_not_screened",
    "prohib_passed_screen",
    "prohib_failed_screen",
    "restricted",
}
_ON_VALUES = {"1", "true", "yes", "on"}
_PHONE_CHARS = set("0123456789+-.() \t")
_URI_USER = re.compile(r"(?:tel|sip|sips):([^@>;,\s]+)", re.IGNORECASE)

_SAFE_VALUES = (
    ("CA_IS_SPAM", "0"),
    ("CA_SPAM_SCORE", "0"),
    ("CA_REPUTATION", "UNKNOWN"),
    ("CA_TOTAL_COMPLAINTS", "0"),
    ("CA_ENTITY_TYPE", "UNKNOWN"),
    ("CA_BIZ_VERIFIED", "0"),
    ("CA_BIZ_NAME", ""),
    ("CA_BIZ_CATEGORY", ""),
    ("CA_BIZ_INDUSTRY", ""),
)


def is_restricted_presentation(value):
    text = (value or "").strip().lower()
    if not text:
        return False
    if text in _RESTRICTED_NAMES or text.startswith("prohib"):
        return True
    if not re.fullmatch(r"-?\d+", text):
        return False
    return (int(text, 10) & _RESTRICTION_MASK) == _RESTRICTED_BIT


def is_phone_number(caller):
    text = (caller or "").strip()
    if not text:
        return False
    if any(ch.isalpha() for ch in text):
        return False
    if not any(ch.isdigit() for ch in text):
        return False
    return all(ch in _PHONE_CHARS for ch in text)


def _to_e164(candidate):
    text = (candidate or "").strip().strip("<>\"'")
    text = text.split(";", 1)[0]
    digits = []
    seen_plus = False
    for ch in text:
        if ch == "+" and not digits and not seen_plus:
            seen_plus = True
            continue
        if ch.isdigit():
            digits.append(ch)
            continue
        if ch in " -.()":
            continue
        return None
    if not seen_plus or not digits or digits[0] == "0":
        return None
    if not 8 <= len(digits) <= 15:
        return None
    return "+" + "".join(digits)


def extract_e164(header):
    if not header:
        return None
    uris = list(_URI_USER.finditer(header))
    if uris:
        for match in uris:
            number = _to_e164(match.group(1))
            if number:
                return number
        return None
    return _to_e164(header)


def pai_lookup_enabled(env, environ):
    argument = (env.get("agi_arg_2") or "").strip().lower()
    if argument:
        return argument in _ON_VALUES
    value = (environ.get(PAI_ENV) or "").strip().lower()
    return value in _ON_VALUES


def _read_agi_env(stdin):
    env = {}
    while True:
        line = stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        env[key.strip()] = value.strip()
    return env


def _command(stdin, stdout, command):
    stdout.write(command + "\n")
    stdout.flush()
    return stdin.readline()


def _parse_result(line):
    text = (line or "").strip()
    marker = "result="
    pos = text.find(marker)
    if pos == -1:
        return ""
    rest = text[pos + len(marker):]
    code, _, tail = rest.partition(" ")
    if code == "0":
        return ""
    start = tail.find("(")
    end = tail.rfind(")")
    if start == -1 or end <= start:
        return ""
    return tail[start + 1:end]


def _get_variable(stdin, stdout, name):
    return _parse_result(_command(stdin, stdout, "GET VARIABLE %s" % name))


def _set_variable(stdin, stdout, key, value):
    text = "" if value is None else str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    _command(stdin, stdout, 'SET VARIABLE %s "%s"' % (key, text))


def _scrub(value, hidden):
    # Remove a withheld network number before the value reaches the callee.
    text = "" if value is None else str(value)
    if not hidden:
        return text
    digits = hidden[1:] if hidden.startswith("+") else hidden
    for token in (hidden, digits):
        if token and re.search(r"(?<!\d)%s(?!\d)" % re.escape(token), text):
            return ""
    return text


def _write_status(stdin, stdout, pairs, status, hidden):
    for key, value in pairs:
        _set_variable(stdin, stdout, key, _scrub(value, hidden))
    _set_variable(stdin, stdout, "CA_LOOKUP_STATUS", _scrub(status, hidden))


def _write_defaults(stdin, stdout, status, hidden=""):
    _write_status(stdin, stdout, _SAFE_VALUES, status, hidden)


def _fetch_lookup(number, auth, urlopen):
    path = urllib.parse.quote(number, safe="")
    req = urllib.request.Request(LOOKUP_URL % path)
    req.add_header("User-Agent", USER_AGENT)
    if auth:
        req.add_header("x-auth", auth)
    with urlopen(req, timeout=LOOKUP_TIMEOUT) as response:
        raw = response.read().decode("utf-8", "replace")
    return json.loads(raw)


def _result_pairs(data):
    body = (data or {}).get("data", {}) if isinstance(data, dict) else {}
    business = body.get("business_info") or {}
    return (
        ("CA_IS_SPAM", "1" if body.get("is_spam") else "0"),
        ("CA_SPAM_SCORE", str(int(body.get("spam_score", 0) or 0))),
        ("CA_REPUTATION", str(body.get("reputation") or "UNKNOWN")),
        ("CA_TOTAL_COMPLAINTS", str(int(body.get("total_complaints", 0) or 0))),
        ("CA_ENTITY_TYPE", str(body.get("entity_type") or "UNKNOWN")),
        ("CA_BIZ_VERIFIED", "1" if business.get("verified") else "0"),
        ("CA_BIZ_NAME", str(business.get("business_name") or "")),
        ("CA_BIZ_CATEGORY", str(business.get("category") or "")),
        ("CA_BIZ_INDUSTRY", str(business.get("industry") or "")),
    )


def _presentations(stdin, stdout, env, caller):
    values = []
    callingpres = env.get("agi_callingpres", "")
    if callingpres:
        values.append(callingpres)
    if not is_phone_number(caller):
        return values
    for name in PRESENTATION_VARS:
        values.append(_get_variable(stdin, stdout, name))
    return values


def _lookup_number(stdin, stdout, env, environ, caller):
    withheld = not is_phone_number(caller)
    if not withheld:
        for value in _presentations(stdin, stdout, env, caller):
            if is_restricted_presentation(value):
                withheld = True
                break
    if not withheld:
        return caller.strip(), False
    if not pai_lookup_enabled(env, environ):
        return None, True
    header = _get_variable(stdin, stdout, PAI_HEADER)
    return extract_e164(header), True


def run(stdin, stdout, urlopen=None, environ=None):
    opener = urllib.request.urlopen if urlopen is None else urlopen
    if environ is None:
        environ = os.environ
    env = _read_agi_env(stdin)
    caller = env.get("agi_callerid", "")
    auth = env.get("agi_arg_1", "")
    number, withheld = _lookup_number(stdin, stdout, env, environ, caller)
    hidden = number if withheld and number else ""
    if not number:
        _write_defaults(stdin, stdout, "skip:withheld")
        return
    try:
        data = _fetch_lookup(number, auth, opener)
    except Exception as exc:
        _write_defaults(stdin, stdout, "fail:%s" % type(exc).__name__, hidden)
        return
    _write_status(stdin, stdout, _result_pairs(data), "ok", hidden)


def main():
    run(sys.stdin, sys.stdout)


if __name__ == "__main__":
    main()
