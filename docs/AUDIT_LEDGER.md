# Append-Only Persistent Audit Ledger

## Durability & Tamper-Evident Architecture
Sovereign Security provides durable, tamper-evident audit storage resistant to silent tampering, host compromise, and crash corruption.

### Record Structure
Every entry encapsulates:
- **Sequence**: Strictly incrementing monotonic integer (`1, 2, 3...`).
- **Who**: Authenticated identity or service account.
- **What**: Action or security event name.
- **When**: ISO-8601 UTC timestamp.
- **Where**: Endpoint, service URI, or resource path.
- **Why**: Justification or trigger condition.
- **Result**: `SUCCESS`, `DENIED`, or `FAILURE`.
- **Details**: Canonicalized key-value metadata.
- **PreviousHash**: SHA-256 hash of the immediately preceding record (Genesis uses 64 zeroes).
- **CurrentHash**: SHA-256 hash of canonical record contents and previousHash.

### Integrity Verification Algorithm
1. Open `$DATA_DIR/audit.ledger`.
2. Parse sequential JSON lines.
3. Validate monotonic sequence (`sequence[i] === sequence[i-1] + 1`).
4. Recompute SHA-256 digest with canonical key sorting.
5. Confirm `record[i].previousHash === record[i-1].currentHash`.
6. Confirm `recomputedHash === record[i].currentHash`.
7. If any check fails: Emit `INTEGRITY_COMPROMISED`, flip gauge `sovereign_audit_ledger_integrity_status` to `0`, and reject subsequent writes.
