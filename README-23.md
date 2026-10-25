# Login Attempt Control System

An authentication control mechanism that locks user accounts after
repeated failed login attempts, to prevent brute-force attacks.

## Objective

Program rate limiting, failed login counters, and temporary account
lockout logic.

## How it works

1. **Failed attempt tracking** — `LoginAttemptController` tracks
   consecutive failures per identifier (username or IP) in memory.
2. **Lockout enforcement** — after 5 consecutive failures (configurable),
   the identifier is locked out for 15 minutes (configurable). While
   locked, further attempts are rejected immediately — the password is
   never even checked — and the lockout auto-expires after the window
   passes.
3. **Audit logging** — every failure, lockout, block, and successful
   login is written to `security_audit.log` with a timestamp, for
   administrative security review.
4. **Brute-force simulation** — `simulate_brute_force()` fires a rapid
   sequence of login attempts at one identifier to prove the system
   correctly blocks the attack, including rejecting the *correct*
   password once locked out, while leaving other users unaffected.

## Usage

```bash
python login_control.py
```

This runs the built-in demo, which:
1. Simulates an 8-attempt brute-force attack on one account (locks after
   attempt 5, blocks attempts 6–8 outright).
2. Shows the correct password still being rejected while locked out.
3. Shows a different user logging in normally, unaffected.
4. Waits for the lockout window to expire, then confirms access is
   restored automatically.

To use it in your own code:

```python
from login_control import LoginAttemptController

controller = LoginAttemptController(max_attempts=5, lockout_seconds=900)
result = controller.attempt_login("alice@example.com", password_correct=False)
# result["status"] is one of: "success", "failure", "locked_out_now", "locked"
```

## Example output

```
--- Simulating brute-force attack on 'alice@example.com' (8 attempts) ---
  Attempt 1: wrong password (1/5 failures)
  Attempt 2: wrong password (2/5 failures)
  Attempt 3: wrong password (3/5 failures)
  Attempt 4: wrong password (4/5 failures)
  Attempt 5: WRONG PASSWORD — account just LOCKED for 10s
  Attempt 6: BLOCKED — account already locked (10s remaining)
  Attempt 7: BLOCKED — account already locked (10s remaining)
  Attempt 8: BLOCKED — account already locked (10s remaining)

--- Attempting the CORRECT password while still locked ---
  Result: locked (10s remaining) — correct password still rejected during lockout

--- A different user logs in normally (unaffected) ---
  Result: success

--- Waiting 10s for lockout to expire ---
  Result after lockout expired: success — access restored
```

## Verification performed

- ✅ 5 consecutive failures trigger a lockout on the 5th attempt.
- ✅ Attempts 6+ during lockout are blocked without checking the password.
- ✅ The correct password is still rejected while locked out.
- ✅ A different identifier (user) is unaffected by another account's
  failures — lockout is per-identifier, not global.
- ✅ After the lockout window expires, the account automatically unlocks
  and a correct login succeeds.
- ✅ All events (failures, lockout, blocks, successes) are written with
  timestamps to `security_audit.log`.

## Project structure

```
login-attempt-control/
├── login_control.py     # LoginAttemptController + brute-force simulation
├── security_audit.log   # generated on first run
└── README.md
```

## Notes

- The demo uses a 10-second lockout window so the auto-unlock behavior
  can be demonstrated quickly without a long wait; the class defaults to
  15 minutes (`lockout_seconds=900`) as specified in the task objective.
- State is kept in memory for this demo (a dict). In a production system
  this would be backed by a database or a shared cache (e.g. Redis) so
  lockout state persists across restarts and scales across multiple
  application servers.
