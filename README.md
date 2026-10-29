# CallerAPI spam shield for Asterisk

This AGI script checks an inbound caller with CallerAPI. It sets channel variables for spam, reputation, and verified business data.

## What the script does

The script reads the caller ID from the AGI environment. It sends one HTTPS request to `GET /api/lookup/{phone}` on `callerapi.com`. The request sends the API key in the `x-auth` header. The timeout is 1.5 seconds.

On success, the script sets the channel variables below. On failure, it sets safe defaults and a `fail:` status.

When the caller ID is withheld, the script does not call the API. It sets `CA_LOOKUP_STATUS` to `skip:withheld`.

UK providers withhold some presentation numbers under Ofcom CLI Guidance 4.18A. The script does not detect the country. It skips every withheld caller ID.

## Channel variables

- `CA_IS_SPAM`: `1` when CallerAPI marks the caller as spam. Otherwise `0`.
- `CA_SPAM_SCORE`: integer spam score. A higher number means the caller looks more like spam.
- `CA_REPUTATION`: label from CallerAPI, such as `UNKNOWN`.
- `CA_TOTAL_COMPLAINTS`: complaint count.
- `CA_ENTITY_TYPE`: entity type from CallerAPI, such as `BUSINESS`, `PERSON`, or `UNKNOWN`.
- `CA_BIZ_VERIFIED`: `1` when CallerAPI marks the business as verified. Otherwise `0`.
- `CA_BIZ_NAME`: business name, or empty.
- `CA_BIZ_CATEGORY`: business category, or empty.
- `CA_BIZ_INDUSTRY`: business industry, or empty.
- `CA_LOOKUP_STATUS`: `ok` on success. `skip:withheld` when the script skips a withheld caller. `fail:` plus an error name on failure.

## Arguments

- `agi_arg_1`: CallerAPI API key. The script sends this key as the `x-auth` header.
- `agi_arg_2`: optional switch for the network number check. Set it to `1` to enable that check. The default is off.

You can set the same switch with the environment variable `CALLERAPI_WITHHELD_PAI`. Accepted values are `1`, `true`, `yes`, and `on`. Any other value leaves the check off. When you set argument 2, that argument overrides the environment variable.

The AGI process inherits the Asterisk service environment. Set `CALLERAPI_WITHHELD_PAI` there when every call should use the same switch.

## Withheld caller ID

The script treats the caller ID as withheld in any of these cases:

1. The caller ID is empty.
2. The caller ID is not a number. `anonymous`, `unknown`, and `restricted` are examples.
3. The presentation flag is restricted or prohibited.

When the caller ID is numeric, the script reads `CALLERID(num-pres)` and `CALLERPRES()`. It also reads `agi_callingpres` when Asterisk sends that value.

These presentation values are restricted: `prohib`, `prohib_not_screened`, `prohib_passed_screen`, `prohib_failed_screen`, and `restricted`. Numeric values 32, 33, 34, and 35 are the same case.

The script then sets the safe defaults and `CA_LOOKUP_STATUS=skip:withheld`. It sends no API request.

An empty caller ID used to set `fail:no_caller`. That status is now `skip:withheld`. The script still does not call the API. Update a dialplan that tests for `fail:no_caller` so it also tests for `skip:withheld`.

This skip is not a credit refund. The API receives no request, so it charges no credit.

## Optional network number lookup

This check is off by default. Enable it with `CALLERAPI_WITHHELD_PAI` or with AGI argument 2.

When the caller ID is withheld and the switch is on, the script reads `PJSIP_HEADER(read,P-Asserted-Identity)`. If that header contains a valid E.164 number, the script checks that number. It writes only the reputation result. It does not write the number to a channel variable. It does not change the caller ID on the call.

If a result field contains that network number, the script clears that field. Do not copy any value from this script into `CALLERID(num)`.

If the header has no valid E.164 number, the script sets `skip:withheld`. It does not call the API.

A valid E.164 number starts with `+`. It does not start with `+0`. It has 8 to 15 digits.

## Example dialplan

This inbound context runs the script first. It blocks high-risk calls. It sets the caller name when CallerAPI returns a verified business.

```ini
[globals]
; API key for CallerAPI.
CALLERAPI_AUTH=your_api_key_here

[inbound]
exten => _X!,1,NoOp(Inbound call from ${CALLERID(num)})
 same => n,Set(__CALLSTART=${EPOCH})
 ; Argument 1 is the API key.
 ; Argument 2 is optional. Set it to 1 to check P-Asserted-Identity on a withheld call.
 same => n,AGI(/var/lib/asterisk/agi-bin/spam_shield.py,${CALLERAPI_AUTH})
 same => n,NoOp(Shield status=${CA_LOOKUP_STATUS} spam=${CA_IS_SPAM} score=${CA_SPAM_SCORE} rep=${CA_REPUTATION} complaints=${CA_TOTAL_COMPLAINTS})

 ; Block a clear spam result.
 same => n,GotoIf($[${CA_IS_SPAM}=1]?block-spam)
 ; Block a high score. Change 80 to match your risk tolerance.
 same => n,GotoIf($[${CA_SPAM_SCORE} > 80]?block-spam)

 ; Send BAD reputation to a lower priority path.
 same => n,GotoIf($["${CA_REPUTATION}" = "BAD"]?low-priority)

 ; Set the caller name for a verified business.
 ; Do not set CALLERID(num) from these variables.
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

[handle-call]
exten => s,1,NoOp(Handle normal inbound call here)
 same => n,Dial(PJSIP/queue_or_agent,30)
 same => n,Voicemail(100@default,u)
 same => n,Hangup()

[ivr_captcha]
exten => s,1,Answer()
 same => n,Playback(custom/press-1-to-continue)
 same => n,WaitExten(5)
exten => 1,1,Goto(handle-call,s,1)
exten => i,1,Hangup()
```

The API key is required. If the key is missing or invalid, the API returns `401` and the script sets `CA_LOOKUP_STATUS` to `fail:HTTPError`.

`skip:withheld` leaves reputation at `UNKNOWN` and spam at `0`. The block rules above do not block that call.

Run the AGI command early in the call so the result can change routing.

## Installation

### Requirements

- A CallerAPI account and API key
- Asterisk 13 or newer, with AGI over standard input and output
- Python 3.7 or newer on the Asterisk host
- Outbound HTTPS access to `callerapi.com`

### Install the script

1. Copy `spam_shield.py` to `/var/lib/asterisk/agi-bin/`.
2. Make it executable with `chmod 0755 /var/lib/asterisk/agi-bin/spam_shield.py`.
3. Set the owner with `chown asterisk:asterisk /var/lib/asterisk/agi-bin/spam_shield.py`.
4. Keep the `#!/usr/bin/env python3` line. Do not add a wrapper.

### Configure Asterisk

1. Add the inbound context from the example above.
2. Set `CALLERAPI_AUTH` in `[globals]`, or pass the key to `AGI()`.
3. Reload the dialplan with `asterisk -rx "dialplan reload"`.

### Network access and timeouts

Allow outbound HTTPS from the Asterisk process to `callerapi.com`. If you use SELinux or AppArmor, allow this AGI egress.

The lookup timeout is 1.5 seconds. On a timeout or any other error, the script sets the safe defaults. It sets `CA_LOOKUP_STATUS` to `fail:` plus the error name. The dialplan then continues.

This script does not request HLR. See the CallerAPI docs when you need HLR.

## Failure behavior

On failure, the variables use the safe defaults. `CA_LOOKUP_STATUS` shows the reason, such as `fail:HTTPError`.

`skip:withheld` is not a failure. It means the script sent no request. An empty caller ID used to report `fail:no_caller`. Use `skip:withheld` for that case now.

Log the variables with `NoOp()` and route from your own policy.

## Troubleshooting

1. Open the Asterisk console with `asterisk -rvvv` and place a test call.
2. Confirm the `NoOp` lines show the AGI variables.
3. Confirm the script is executable and the shebang points to Python 3.
4. Confirm the host can open HTTPS to `callerapi.com`.
5. Confirm the API key arrives as `agi_arg_1`.
6. If the status is `skip:withheld`, the caller ID is empty, not a number, or the presentation is restricted.
7. To check a withheld call by its network number, set `CALLERAPI_WITHHELD_PAI` to `1` or pass `1` as AGI argument 2.

## Tests

Run this command from the repository root:

```bash
python3 -m unittest tests.test_spam_shield
```

The tests do not call the live API. They use an Ofcom drama number and a 555-01XX number.

## References

CallerAPI spam score and HLR: `https://docs.callerapi.com/spam-score-hlr-19887237e0`

## Video demo

https://github.com/user-attachments/assets/a5dae998-7997-40c5-823b-efbf7a4c3392
