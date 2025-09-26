#!/usr/bin/env python3
import urllib.request
import urllib.parse
import json
import sys

def read_agi_env():
    env = {}
    for line in sys.stdin:
        line = line.strip()
        if not line: break
        if ':' in line:
            k, v = line.split(':', 1)
            env[k.strip()] = v.strip()
    return env

def setvar(k, v):
    v = "" if v is None else str(v)
    # escape backslashes and quotes, then wrap in quotes so it's safe
    v = v.replace("\\", "\\\\").replace('"', '\\"')
    sys.stdout.write(f'SET VARIABLE {k} "{v}"\n')
    sys.stdout.flush()
    sys.stdin.readline()

def main():
    env = read_agi_env()
    caller = env.get('agi_callerid', '')
    auth = env.get('agi_arg_1', '')

    def fail(status="fail"):
        for k, v in [
            ("CA_IS_SPAM","0"),
            ("CA_SPAM_SCORE","0"),
            ("CA_REPUTATION","UNKNOWN"),
            ("CA_TOTAL_COMPLAINTS","0"),
            ("CA_ENTITY_TYPE","UNKNOWN"),
            ("CA_BIZ_VERIFIED","0"),
            ("CA_BIZ_NAME",""),
            ("CA_BIZ_CATEGORY",""),
            ("CA_BIZ_INDUSTRY",""),
            ("CA_LOOKUP_STATUS",status),
        ]: setvar(k, v)

    if not caller:
        return fail("fail:no_caller")

    try:
        num_path = urllib.parse.quote(caller, safe='')
        req = urllib.request.Request(f"https://callerapi.com/api/lookup/{num_path}")
        req.add_header("User-Agent", "Asterisk-CallerAPI/1.0")
        if auth: req.add_header("x-auth", auth)

        with urllib.request.urlopen(req, timeout=1.5) as r:
            data = json.loads(r.read().decode('utf-8', 'replace'))
        d = (data or {}).get("data", {}) if isinstance(data, dict) else {}

        is_spam = 1 if d.get("is_spam") else 0
        score = int(d.get("spam_score", 0) or 0)
        reputation = str(d.get("reputation") or "UNKNOWN")
        total_comp = int(d.get("total_complaints", 0) or 0)
        entity = str(d.get("entity_type") or "UNKNOWN")

        b = d.get("business_info") or {}
        biz_verified = 1 if b.get("verified") else 0
        biz_name = str(b.get("business_name") or "")
        biz_category = str(b.get("category") or "")
        biz_industry = str(b.get("industry") or "")

        setvar("CA_IS_SPAM", str(is_spam))
        setvar("CA_SPAM_SCORE", str(score))
        setvar("CA_REPUTATION", reputation)
        setvar("CA_TOTAL_COMPLAINTS", str(total_comp))
        setvar("CA_ENTITY_TYPE", entity)
        setvar("CA_BIZ_VERIFIED", str(biz_verified))
        setvar("CA_BIZ_NAME", biz_name)
        setvar("CA_BIZ_CATEGORY", biz_category)
        setvar("CA_BIZ_INDUSTRY", biz_industry)
        setvar("CA_LOOKUP_STATUS", "ok")

    except Exception as e:
        fail(f"fail:{type(e).__name__}")

if __name__ == "__main__":
    main()
