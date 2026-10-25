#!/usr/bin/env python3
"""
Login Attempt Control System
------------------------------
An authentication control mechanism that locks user accounts after
repeated failed login attempts, to prevent brute-force attacks.

Design:
  - Failed attempts are tracked per identifier (username or IP) in memory.
  - After 5 consecutive failures, the identifier is locked out for 15
    minutes (configurable).
  - A successful login resets the failure counter.
  - Every lockout event is written to an audit log for administrative
    review.
  - A brute-force simulation demonstrates the system correctly blocking
    a rapid password-guessing loop.

Usage:
    python login_control.py            # runs the built-in demo/simulation
    (or import LoginAttemptController into another script)

Author: <your name>
"""

import time
import datetime
import logging

# ---------------------------------------------------------------------------
# Audit logging setup — Step 3: log lockout events for administrative audit
# ---------------------------------------------------------------------------
logging.basicConfig(
    filename="security_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("login_attempt_control")

# Also echo audit events to the console for this demo, so the CLI run is
# self-explanatory without needing to open the log file separately.
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(console)


# ---------------------------------------------------------------------------
# Step 1 & 2: track failed attempts, enforce lockout after N consecutive
# failures, for a configurable lockout duration
# ---------------------------------------------------------------------------
class LoginAttemptController:
    def __init__(self, max_attempts: int = 5, lockout_seconds: int = 900):
        """
        max_attempts   : consecutive failures allowed before lockout (default 5)
        lockout_seconds: lockout duration in seconds (default 900 = 15 minutes)
        """
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        # In-memory store: { identifier: {"failures": int, "locked_until": float|None} }
        self._state = {}

    def _get_record(self, identifier: str) -> dict:
        if identifier not in self._state:
            self._state[identifier] = {"failures": 0, "locked_until": None}
        return self._state[identifier]

    def is_locked(self, identifier: str) -> bool:
        record = self._get_record(identifier)
        if record["locked_until"] is None:
            return False
        if time.time() >= record["locked_until"]:
            # Lockout window has expired — clear it automatically.
            record["locked_until"] = None
            record["failures"] = 0
            return False
        return True

    def remaining_lockout_seconds(self, identifier: str) -> float:
        record = self._get_record(identifier)
        if record["locked_until"] is None:
            return 0.0
        return max(0.0, record["locked_until"] - time.time())

    def attempt_login(self, identifier: str, password_correct: bool) -> dict:
        """
        Process one login attempt for `identifier`.
        Returns a result dict describing what happened.
        """
        timestamp = datetime.datetime.now().isoformat(timespec="seconds")

        if self.is_locked(identifier):
            remaining = round(self.remaining_lockout_seconds(identifier))
            logger.info(
                f"BLOCKED  | identifier={identifier} | attempt rejected — "
                f"account locked, {remaining}s remaining | time={timestamp}"
            )
            return {"status": "locked", "remaining_seconds": remaining}

        record = self._get_record(identifier)

        if password_correct:
            record["failures"] = 0
            record["locked_until"] = None
            logger.info(f"SUCCESS  | identifier={identifier} | login succeeded | time={timestamp}")
            return {"status": "success"}

        # Failed attempt
        record["failures"] += 1
        logger.info(
            f"FAILURE  | identifier={identifier} | failed attempt "
            f"{record['failures']}/{self.max_attempts} | time={timestamp}"
        )

        if record["failures"] >= self.max_attempts:
            record["locked_until"] = time.time() + self.lockout_seconds
            logger.info(
                f"LOCKOUT  | identifier={identifier} | account locked for "
                f"{self.lockout_seconds}s after {record['failures']} consecutive "
                f"failures | time={timestamp}"
            )
            return {"status": "locked_out_now", "lockout_seconds": self.lockout_seconds}

        return {"status": "failure", "failures": record["failures"]}


# ---------------------------------------------------------------------------
# Step 4: test the system against a simulated brute-force attempt loop
# ---------------------------------------------------------------------------
def simulate_brute_force(controller: LoginAttemptController, identifier: str,
                          attempts: int, correct_password_attempt_index: int = None):
    """
    Simulates `attempts` rapid login attempts against `identifier`, using
    wrong passwords except optionally one correct attempt at a given index
    (to prove a locked-out account is blocked even with the right password).
    """
    print(f"\n--- Simulating brute-force attack on '{identifier}' "
          f"({attempts} attempts) ---")
    for i in range(1, attempts + 1):
        correct = (i == correct_password_attempt_index)
        result = controller.attempt_login(identifier, password_correct=correct)
        if result["status"] == "locked":
            print(f"  Attempt {i}: BLOCKED — account already locked "
                  f"({result['remaining_seconds']}s remaining)")
        elif result["status"] == "locked_out_now":
            print(f"  Attempt {i}: WRONG PASSWORD — account just LOCKED for "
                  f"{result['lockout_seconds']}s")
        elif result["status"] == "success":
            print(f"  Attempt {i}: LOGIN SUCCESSFUL")
        else:
            print(f"  Attempt {i}: wrong password "
                  f"({result['failures']}/{controller.max_attempts} failures)")


def main():
    # Short lockout window (10s) for this demo so the auto-unlock behavior
    # can also be shown quickly. In production use 900s (15 min) as above.
    controller = LoginAttemptController(max_attempts=5, lockout_seconds=10)

    # Scenario 1: attacker tries 8 rapid wrong-password guesses.
    # Expect: first 5 tracked as failures, 5th triggers lockout, attempts
    # 6-8 are blocked outright without even checking the password.
    simulate_brute_force(controller, "alice@example.com", attempts=8)

    # Scenario 2: even the CORRECT password is rejected while locked out.
    print(f"\n--- Attempting the CORRECT password while still locked ---")
    result = controller.attempt_login("alice@example.com", password_correct=True)
    print(f"  Result: {result['status']} "
          f"({result.get('remaining_seconds', 0)}s remaining) — correct "
          f"password still rejected during lockout")

    # Scenario 3: a different, legitimate user is unaffected by attacker's
    # failures on another account (per-identifier isolation).
    print(f"\n--- A different user logs in normally (unaffected) ---")
    result = controller.attempt_login("bob@example.com", password_correct=True)
    print(f"  Result: {result['status']}")

    # Scenario 4: wait out the lockout window, then confirm access is restored.
    print(f"\n--- Waiting {controller.lockout_seconds}s for lockout to expire ---")
    time.sleep(controller.lockout_seconds + 1)
    result = controller.attempt_login("alice@example.com", password_correct=True)
    print(f"  Result after lockout expired: {result['status']} — access restored")

    print("\nAudit log written to security_audit.log")


if __name__ == "__main__":
    main()
