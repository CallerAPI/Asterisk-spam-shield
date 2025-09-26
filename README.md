# CallerAPI Spam Shield for Asterisk (AGI)

A compact AGI script for Asterisk that checks inbound caller reputation via CallerAPI, flags spam, and sets CNAM/business metadata when the caller is a verified business.

## What this helps you achieve
- **Reduce spam/scam calls**: quickly classify and score callers, enabling early call blocking or special handling.
- **Improve caller ID quality**: populate CNAM-like business fields for verified companies.
- **Route intelligently**: use reputation, spam score, and complaint totals to influence call flow.

## How it works
- The AGI reads the Asterisk AGI environment to obtain the caller ID number and an API key argument.
- It performs a fast HTTPS lookup to `GET /api/lookup/{phone}` on `callerapi.com`, sending the API key in the `x-auth` header (timeout 1.5s).
- On success, it sets channel variables with spam/reputation and business metadata. On failure or missing caller ID, it sets safe defaults and indicates failure status.

### Channel variables set
- `CA_IS_SPAM` — `1` if flagged as spam, else `0`.
- `CA_SPAM_SCORE` — integer spam score (higher means more spammy).
- `CA_REPUTATION` — string label returned by CallerAPI (e.g., `UNKNOWN`).
- `CA_TOTAL_COMPLAINTS` — integer count of complaints.
- `CA_ENTITY_TYPE` — string entity type returned by CallerAPI (e.g., `BUSINESS`, `PERSON`, `UNKNOWN`).
- `CA_BIZ_VERIFIED` — `1` if CallerAPI flags business as verified, else `0`.
- `CA_BIZ_NAME` — business name if available.
- `CA_BIZ_CATEGORY` — business category if available.
- `CA_BIZ_INDUSTRY` — business industry if available.
- `CA_LOOKUP_STATUS` — `ok` on success; `fail:*` on failure (e.g., `fail:no_caller`, `fail:HTTPError`).

### Input parameters (AGI args)
- `agi_arg_1` — CallerAPI API key (required). Passed as `x-auth` header.

## Example: extensions.conf
Below is a practical inbound context example. It runs the shield early, blocks high‑risk calls, and sets caller name when a verified business is detected.

```ini
[globals]
; Store your API key in a global
CALLERAPI_AUTH=your_api_key_here

[inbound]
; Assume inbound DID is sent to this context via your trunks
exten => _X!,1,NoOp(Inbound call from ${CALLERID(num)})
 same => n,Set(__CALLSTART=${EPOCH})
 ; Run the AGI: pass API key as first argument (required)
 same => n,AGI(/var/lib/asterisk/agi-bin/spam_shield.py,${CALLERAPI_AUTH})
 same => n,NoOp(Shield status=${CA_LOOKUP_STATUS} spam=${CA_IS_SPAM} score=${CA_SPAM_SCORE} rep=${CA_REPUTATION} complaints=${CA_TOTAL_COMPLAINTS})

 ; Hard block if clearly spam
 same => n,GotoIf($[${CA_IS_SPAM}=1]?block-spam)
 ; Optional: block if score above a threshold
 same => n,GotoIf($[${CA_SPAM_SCORE} > 80]?block-spam)

 ; Optional: deprioritize or route "BAD" reputation to voicemail or CAPTCHA
 same => n,GotoIf($["${CA_REPUTATION}" = "BAD"]?low-priority)

 ; If verified business and we have a name, set CNAM for agent screens and CDRs
 same => n,GotoIf($[${CA_BIZ_VERIFIED}=1 & "${CA_BIZ_NAME}" != ""]?set-cnam)
 same => n(normal-flow),NoOp(Normal routing)
 same => n,Goto(handle-call,s,1)

 same => n(set-cnam),NoOp(Setting caller name to ${CA_BIZ_NAME})
 same => n,Set(CALLERID(name)=${CA_BIZ_NAME})
 same => n,Goto(normal-flow)

 same => n(low-priority),NoOp(Low priority routing for BAD reputation)
 same => n,Goto(ivr_captcha,s,1)

 same => n(block-spam),NoOp(Blocking spam caller. Score=${CA_SPAM_SCORE} Complaints=${CA_TOTAL_COMPLAINTS})
 same => n,Answer()
 same => n,Wait(1)
 same => n,Playback(ss-noservice)
 same => n,Hangup()

; Example downstream handler
[handle-call]
exten => s,1,NoOp(Handle normal inbound call here)
 same => n,Dial(PJSIP/queue_or_agent,30)
 same => n,Voicemail(100@default,u)
 same => n,Hangup()

; Example IVR CAPTCHA for suspicious calls
[ivr_captcha]
exten => s,1,Answer()
 same => n,Playback(custom/press-1-to-continue)
 same => n,WaitExten(5)
exten => 1,1,Goto(handle-call,s,1)
exten => i,1,Hangup()
```

Notes:
- API key is required. If omitted or invalid, the API will return `401` and the script will set safe defaults with `CA_LOOKUP_STATUS=fail:HTTPError`.
- Thresholds (e.g., `CA_SPAM_SCORE > 80`) should match your risk tolerance.
- Run the AGI early in the call to influence routing decisions.

## Installation

### 1) Requirements
- [CallerAPI](https://callerapi.com) account and API key
- Asterisk 13+ (AGI over STDIN/STDOUT)
- Python 3.7+ on the Asterisk host
- Outbound HTTPS access to `callerapi.com`

### 2) Deploy the AGI script
1. Copy `spam_shield.py` to Asterisk AGI directory:
   - Common path: `/var/lib/asterisk/agi-bin/`
2. Ensure it is executable and owned by the Asterisk user:
   - `chmod 0755 /var/lib/asterisk/agi-bin/spam_shield.py`
   - `chown asterisk:asterisk /var/lib/asterisk/agi-bin/spam_shield.py` (adjust user/group as needed)
3. The script includes a `#!/usr/bin/env python3` shebang; no wrapper is required.

### 3) Configure Asterisk
1. Add or update your inbound context in `extensions.conf` using the example above.
2. Define `CALLERAPI_AUTH` in `[globals]` or pass the key inline to `AGI()`.
3. Reload dialplan: `asterisk -rx "dialplan reload"`.

### 4) SELinux/AppArmor and networking
- Ensure the Asterisk process can make outbound HTTPS requests.
- If using SELinux/AppArmor, allow AGI network egress.

### 5) Timeouts and reliability
- The AGI uses a 1.5s lookup timeout. On timeout or any error, it sets defaults and `CA_LOOKUP_STATUS=fail:*` so your dialplan continues.
- This script does not request HLR; see CallerAPI docs if you need HLR-specific behavior.

## Return values and failure behavior
- On failure, variables are set to safe defaults and `CA_LOOKUP_STATUS` indicates the reason (e.g., `fail:no_caller`, HTTP/network errors).
- Use `NoOp()` logs for visibility and route based on your policies.

## Troubleshooting
- Run a live test on the Asterisk console: `asterisk -rvvv` and place a test call; confirm the `NoOp` lines show variables from the AGI.
- Verify script permissions and that the shebang points to Python 3.
- Check network/firewall rules permitting HTTPS to `callerapi.com`.
- Ensure the API key reaches the script as `${agi_arg_1}` (and thus the `x-auth` header).

## References
- CallerAPI: Spam score + HLR — `https://docs.callerapi.com/spam-score-hlr-19887237e0`

## Video demo
https://github.com/user-attachments/assets/a5dae998-7997-40c5-823b-efbf7a4c3392


