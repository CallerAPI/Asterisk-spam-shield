# Changelog

## 2026-10-29

### Changed

- The script skips the CallerAPI request when the caller ID is empty.
- The script skips the request when the caller ID is not a number. `anonymous`, `unknown`, and `restricted` are examples.
- The script skips the request when `CALLERID(num-pres)` or `CALLERPRES()` is restricted or prohibited.
- `agi_callingpres` values 32, 33, 34, and 35 also skip the request.
- These calls set `CA_LOOKUP_STATUS` to `skip:withheld`.
- An empty caller ID used to set `fail:no_caller`. That status is now `skip:withheld`. The script still sends no request.

### Added

- The script can check a valid E.164 number in `P-Asserted-Identity` when the caller ID is withheld.
- Set `CALLERAPI_WITHHELD_PAI` to `1` to enable that check. You can also set AGI argument 2 to `1`.
- Argument 2 overrides the environment variable. The default is off.
- The script stores the reputation result only. It does not show that network number to the callee.
- Tests cover an empty caller ID, `anonymous`, `unknown`, a restricted presentation, and the optional network number check.

The skip sends no request. It is not a credit refund.
