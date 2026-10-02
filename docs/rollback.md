# Anti-rollback

## The attack

An attacker with write access restores an older *consistent* container
snapshot (older `CURRENT`, older manifest chain, older blobs). Without a
witness outside the container, AEAD alone cannot detect this: every old
file is still individually valid.

## The witness

`state/ctl.bin` records, after every commit:

* `max_seen_generation` — the highest generation ever observed,
* `seen_manifest_hash` — hash of that generation's manifest file.

On unlock, after the manifest hash chain verifies:

```text
if generation < control.max_seen_generation → RollbackDetected (LOCKED, conf 95)
```

A *same*-generation manifest whose hash differs from the witnessed hash also
raises `rollback.detected`, but the read continues (the manifest is still
verified against `CURRENT`, the chain, and the vault id) and the witness
re-anchors to the observed pair — a second concurrent writer must not brick
the vault, and forging a self-consistent manifest still requires the meta key.

The witness is stored with DPAPI protection (entropy = `vault_id`); if DPAPI
is unavailable it degrades to a plaintext record — the file still functions
as a witness, but an attacker who can write the whole vault directory can
reset it. This is a documented limitation (see `threat-model.md`).

The check runs inside `read_verified_manifest_bytes`, which **every** unlock
path must pass — including the domain-rekey resume path — so recovery
mechanisms can never become a rollback bypass.

## Chain, pointer, witness

| Layer | Detects |
|---|---|
| `sha256(manifest) ∈ CURRENT` | manifest edited in place |
| `prev_manifest_hash` chain | manifest substituted/reordered |
| `vault_id` in manifest prefix | manifest from another vault |
| AEAD under domain keys | any body mutation without keys |
| witnessed generation | whole-container snapshot rollback |

## Handling

`RollbackDetected` maps to **LOCKED** with session destruction
(confidence 95): the session is dropped, writes stay blocked, and the event
is queued for the audit log. Restoration of a legitimate backup that is
older than the witness therefore requires a fresh authentication — a
successful unlock steps the state down to `SUSPICIOUS`, from where the
operator can `acknowledge_findings` back to `NORMAL`. Vault chooses to fail
closed rather than silently accept rolled-back state.

## What is *not* protected

* First unlock after `ctl.bin` loss (no witness yet — control state is
  rebuilt with `max_seen_generation = 0`; a `control.unavailable` warning
  is recorded).
* Rolling back *everything including the witness* — undetectable by design;
  a remote/unrelated witness would be required.
* `created_at_ms`/timestamps are informational, not trusted.
