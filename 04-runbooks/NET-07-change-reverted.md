# NET-07-change-reverted: A firewall policy change was not confirmed and reverted itself

**Severity:** High, closed by hand

## Why it matters
apply_policy.py arms a revert on the box before each change; a revert means the change cut the admin off (or the change was interrupted).

## Check
1. What was being changed (change record, `git log` of 03-firewall).
1. Is the old policy back: run `05-drills/policy_matrix.sh`.

## Fix
1. Fix the change (usually a rule ordering or a missing admin/anti-lockout path) and apply it again in a window.

## Escalate
Change owner.

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
