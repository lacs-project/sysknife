//! Forward Ed25519-signed hash chain for the audit log.
//!
//! Each `transactions` row stores `chain_hash` and `prev_chain_hash` columns.
//! On insert, the daemon computes
//!
//! ```text
//! chain_hash = ed25519_sign(canonical(immutable_fields) || prev_chain_hash, signing_key)
//! ```
//!
//! and stores both (the signature is hex-encoded; the first row in a chain has
//! `prev_chain_hash = ""`). Ed25519 signatures are deterministic (RFC 8032), so
//! the same content always produces the same `chain_hash`.
//!
//! Verification (`sysknife audit verify`) walks rows in `seq` order and checks
//! each row's signature **with the public key**, reporting the first broken
//! link. Because verification needs only the public key, an auditor or a
//! central log aggregator can verify the chain **without holding the private
//! key** — they cannot forge entries. This is the property a symmetric MAC
//! (the previous HMAC-SHA256 design) could not provide: with an HMAC, the
//! verifier and the forger are the same principal.
//!
//! ## Threat model
//!
//! - **Non-repudiation (asymmetric).** The daemon signs with the private key;
//!   anyone with the exported public key (`<key>.pub`) can verify but not
//!   forge. A compromise of the verifier does not enable forgery.
//! - **Compromised host / root.** An attacker who reads the private key file
//!   can forge *future* entries. Mitigation is to anchor signed checkpoints to
//!   an append-only external sink (see `checkpoint_sink`) so that later
//!   tampering with past entries becomes *detectable* and the tamper window is
//!   bounded to "after compromise".
//! - **Tail truncation** is undetectable by the chain walk alone: an attacker
//!   who deletes the last K rows leaves a still-consistent chain. It is caught
//!   by anchoring signed checkpoints to an independent append-only sink, since
//!   a truncated chain can no longer reproduce a previously anchored
//!   `(seq, chain_tip)` (see `verify_checkpoints` and `checkpoint_sink`). The
//!   best-effort `audit_watermark` journald forward is a lighter complement.
//! - **In-flight modification** between insert and read is mitigated by
//!   computing the signature *before* INSERT and writing it in the same SQL
//!   statement.
//! - **Status mutations are not in the chain.** The mutable `status` field
//!   is intentionally excluded — the chain protects the *authorisation
//!   decision* (immutable fields captured at insert time), not the live
//!   execution state. A future append-only `audit_events` table will
//!   chain status transitions if the threat model demands it.
//!
//! ## Key management
//!
//! The Ed25519 private key (a 32-byte seed) lives in a file. By default the
//! path is `<db_dir>/audit-key` (sibling of the SQLite database, or of
//! whatever directory `sysknife_core::default_database_path` resolves to in
//! production), and the env var `SYSKNIFE_AUDIT_KEY_PATH` overrides it for
//! systemd unit drop-ins (typically `/etc/sysknife/audit-key`). The file is
//! created with mode `0o600` on first daemon start if it does not exist;
//! subsequent runs refuse to start if it is world-readable. The public key is
//! written alongside as `<key>.pub` (hex) for auditors and aggregators.
//!
//! Future epochs (key rotation): each row already carries a `key_id`
//! column. A planned rotation flow appends a checkpoint row signed with the
//! outgoing key whose payload references both public-key fingerprints;
//! verification walks the chain through epoch boundaries by looking up each
//! row's `key_id` in a directory of retired public keys. For now, all rows use
//! `key_id = "v1"` and rotation is manual (delete the chain, regenerate).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::path::{Path, PathBuf};
use sysknife_types::RiskLevel;
use zeroize::Zeroize;

/// Stable identifier for the current key generation. Stored in every row.
/// Tied to the schema, not the key bytes — rotation will introduce `"v2"` etc.
pub const CURRENT_KEY_ID: &str = "v1";

/// Hex-encoded length of an Ed25519 signature (64 raw bytes → 128 hex chars).
pub const HASH_HEX_LEN: usize = 128;

/// Loaded Ed25519 signing key + its identifier. Construct via
/// [`AuditKey::load_or_generate`].
///
/// `Clone` is intentional: the audit-verify CLI needs to load the key once
/// and share it between the SQLite read-only path and the Postgres pool.
///
/// `Debug` is implemented manually to redact the signing key. A derived
/// `Debug` would dump the private key via any `tracing::debug!("{key:?}")`
/// or `dbg!(key)` site, which would leak the audit secret into journald.
/// We keep `key_id` visible because operators need to identify which key
/// generation a record belongs to when triaging chain breaks.
#[derive(Clone)]
pub struct AuditKey {
    key_id: String,
    signing: SigningKey,
}

impl std::fmt::Debug for AuditKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the private key. A derived `Debug` (or printing the
        // signing key) would leak the audit secret into journald via any
        // `tracing::debug!("{key:?}")`. `key_id` is not secret and is kept
        // visible for triaging chain breaks.
        f.debug_struct("AuditKey")
            .field("key_id", &self.key_id)
            .field("signing", &format_args!("<redacted signing key>"))
            .finish()
    }
}

// The `SigningKey` zeroizes its secret scalar on drop (ed25519-dalek `zeroize`
// feature), so no manual `Drop` is needed to keep the private key out of
// post-free memory.

#[derive(Debug, thiserror::Error)]
pub enum AuditKeyError {
    #[error("io error reading audit key {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "audit key file {path} has unsafe permissions {mode:#o}; \
         tighten with `chmod 600 {path:?}` and restart"
    )]
    UnsafePermissions { path: PathBuf, mode: u32 },
    #[error(
        "audit key file {path} is too short ({len} bytes); \
         expected at least 32 bytes of random material"
    )]
    KeyTooShort { path: PathBuf, len: usize },
}

impl AuditKey {
    /// Load the audit key from `path`. If the file does not exist, generate a
    /// 32-byte cryptographically random key and write it with mode `0o600`.
    ///
    /// On every load (including freshly generated), the file's permissions
    /// are checked: any bit beyond `0o600` for owner-only access is rejected
    /// — a world-readable audit key is a self-defeating audit chain.
    pub fn load_or_generate(path: &Path) -> Result<Self, AuditKeyError> {
        if !path.exists() {
            generate_key_at(path)?;
        }

        let metadata = std::fs::metadata(path).map_err(|e| AuditKeyError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            // Group or world bits set — reject.
            return Err(AuditKeyError::UnsafePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }

        let mut key_bytes = std::fs::read(path).map_err(|e| AuditKeyError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if key_bytes.len() < 32 {
            return Err(AuditKeyError::KeyTooShort {
                path: path.to_path_buf(),
                len: key_bytes.len(),
            });
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes[..32]);
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        key_bytes.zeroize();

        Ok(Self {
            key_id: CURRENT_KEY_ID.to_string(),
            signing,
        })
    }

    /// Construct a key from a 32-byte seed. For tests only — production builds
    /// always go through [`Self::load_or_generate`] for the permission check.
    #[cfg(test)]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self {
            key_id: CURRENT_KEY_ID.to_string(),
            signing,
        }
    }

    /// Stable identifier for this key generation.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Compute the chain signature for `content` linked to `prev_chain_hash`.
    ///
    /// Hex-encoded Ed25519 signature over `canonical(content) || prev_chain_hash`.
    /// Deterministic (RFC 8032): identical inputs always yield the same value.
    pub fn chain_hash(&self, content: &ChainContent, prev_chain_hash: &str) -> String {
        let sig = self.signing.sign(&chain_message(content, prev_chain_hash));
        hex::encode(sig.to_bytes())
    }

    /// The public verifying key for this audit key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Hex-encoded 32-byte Ed25519 public key. Safe to publish; auditors use it
    /// to verify the chain without the ability to forge entries.
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }
}

/// Message signed for a row: `ROW_DOMAIN || canonical(content) || prev_chain_hash`.
///
/// The leading domain tag separates row signatures from checkpoint signatures
/// so a signature produced in one context can never verify in the other, even
/// if the framed fields were ever to overlap.
fn chain_message(content: &ChainContent, prev_chain_hash: &str) -> Vec<u8> {
    let mut msg = b"sysknife-audit-row-v1\x1f".to_vec();
    msg.extend_from_slice(&content.canonical_bytes());
    msg.extend_from_slice(prev_chain_hash.as_bytes());
    msg
}

/// Generate a 32-byte random key and write it to `path` with mode `0o600`.
/// Parent directory is created with mode `0o700` if missing.
fn generate_key_at(path: &Path) -> Result<(), AuditKeyError> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| AuditKeyError::Io {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
        }
    }

    let mut bytes = [0u8; 32];
    fill_random(&mut bytes).map_err(|e| AuditKeyError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| AuditKeyError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    f.write_all(&bytes).map_err(|e| AuditKeyError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    f.sync_all().map_err(|e| AuditKeyError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    // Write the public key alongside as `<key>.pub` (hex). Not secret: it lets
    // an auditor or aggregator verify the chain without the private key.
    let signing = SigningKey::from_bytes(&bytes);
    let pub_hex = hex::encode(signing.verifying_key().to_bytes());
    bytes.zeroize();
    let mut pub_path = path.as_os_str().to_os_string();
    pub_path.push(".pub");
    std::fs::write(&pub_path, format!("{pub_hex}\n")).map_err(|e| AuditKeyError::Io {
        path: PathBuf::from(pub_path),
        source: e,
    })?;
    Ok(())
}

/// Fill `buf` with bytes from the kernel CSPRNG via `/dev/urandom`.
fn fill_random(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read as _;
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)
}

/// Immutable fields hashed into the chain. Status is intentionally absent —
/// see module docs.
///
/// # Security contract — chain-content immutability
///
/// Every field in this struct is captured **once** at INSERT time and baked
/// into `chain_hash = ed25519_sign(canonical(self) || prev_chain_hash, key)`.
/// After the row is written the hash is a one-time commitment: **no field
/// in this struct may ever be mutated in place**.
///
/// `summary` is the field most likely to attract a future "let me just fix
/// that typo" API. **Do not add an `update_summary` (or similar) function.**
/// If a correction is genuinely needed, choose one of the two safe options:
///
/// 1. **Insert a corrective row** — a new transaction row that references the
///    original `transaction_id` in its own `summary`, leaving the original
///    row and its chain hash untouched.
/// 2. **Extend the chain protocol** — introduce a dedicated amendment record
///    type with its own chain link, so that both the original commitment and
///    the correction are auditable.
///
/// Any other approach silently breaks chain integrity: `verify_chain` will
/// flag the modified row as `Broken` because the stored signature will no
/// longer verify against the row's content.
///
/// The canonical serialisation is stable across SQLite/Postgres backends.
/// Each field is emitted as
///
/// ```text
///     <tag-name> 0x1E <tag-value> 0x1F
/// ```
///
/// where `0x1E` is the *tag/value* separator within a single field and `0x1F`
/// is the *field* separator that terminates the field and introduces the
/// next one. We use the ASCII C0 byte values RS (0x1E) and US (0x1F)
/// because they are guaranteed not to appear in any normal text field, but
/// **our role assignment is the inverse of the ASCII C0 convention**
/// (where RS = "record separator" and US = "unit separator"). The names
/// are kept in the source for byte-level traceability against the canonical
/// buffer, not as a claim about ASCII semantics.
///
/// Inside a value, the four
/// bytes `\\`, NUL, `RS`, `US` are escaped to `\\\\`, `\\0`, `\\1E`, `\\1F`
/// respectively. The escape table is **prefix-free** (every escape starts
/// with `\\`), so any value can be injected without ambiguity. See
/// `push_field` for the implementation and tests for the round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainContent<'a> {
    pub seq: u64,
    pub key_id: &'a str,
    pub transaction_id: &'a str,
    pub request_id: &'a str,
    pub request_hash: &'a str,
    pub action_name: &'a str,
    pub risk_level: RiskLevel,
    /// Human-readable description of the planned action.
    ///
    /// **Immutable after insert.** This field is included in the chain hash
    /// (see [`ChainContent`] struct-level doc). It MUST NOT be updated after
    /// the row is written — doing so silently invalidates `chain_hash` and
    /// will be detected as `VerifyOutcome::Broken` by `sysknife audit verify`.
    /// See the struct-level security contract for the only safe correction
    /// strategies.
    pub summary: &'a str,
    /// `None` for un-approved (preview-only) records; serialised as empty.
    pub approval_id: Option<&'a str>,
    /// JSON-canonical (sorted keys) array of warning strings.
    pub warnings_json: &'a str,
    pub created_at: &'a str,
}

impl<'a> ChainContent<'a> {
    /// Stable canonical encoding of every field. Within each field the
    /// `0x1E` byte separates tag from value, and `0x1F` terminates the field;
    /// raw NUL becomes the two-byte escape `\0`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let risk_level_str = match self.risk_level {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
        };
        let approval = self.approval_id.unwrap_or("");

        let mut buf = Vec::with_capacity(512);
        // Each field is `tag 0x1E value 0x1F`; tags make the canonical form
        // self-describing for forensics.
        push_field(&mut buf, "seq", &self.seq.to_string());
        push_field(&mut buf, "key_id", self.key_id);
        push_field(&mut buf, "transaction_id", self.transaction_id);
        push_field(&mut buf, "request_id", self.request_id);
        push_field(&mut buf, "request_hash", self.request_hash);
        push_field(&mut buf, "action_name", self.action_name);
        push_field(&mut buf, "risk_level", risk_level_str);
        push_field(&mut buf, "summary", self.summary);
        push_field(&mut buf, "approval_id", approval);
        push_field(&mut buf, "warnings_json", self.warnings_json);
        push_field(&mut buf, "created_at", self.created_at);
        buf
    }
}

/// Append `tag<RS>value<US>` to `buf`, escaping any byte that could otherwise
/// alias one of the framing characters or another escape sequence.
///
/// The escape table is **prefix-free**: every escape starts with `\` (0x5C)
/// followed by a tag that cannot itself be the start of a different escape.
/// Concretely:
///
/// | Raw byte | Escape       |
/// |---------:|--------------|
/// | `\\`     | `\\\\`       |
/// | `\x00`   | `\\0`        |
/// | `\x1E`   | `\\1E`       |
/// | `\x1F`   | `\\1F`       |
///
/// The `\\` escape MUST come first: without it, a field value containing the
/// literal two-byte sequence `\` + `0` would canonicalise to the same bytes
/// as a raw NUL and produce a chain-signature collision.
fn push_field(buf: &mut Vec<u8>, tag: &str, value: &str) {
    buf.extend_from_slice(tag.as_bytes());
    buf.push(0x1E); // tag/value separator (ASCII RS byte, but used inversely — see ChainContent doc)
    for b in value.bytes() {
        match b {
            b'\\' => buf.extend_from_slice(b"\\\\"),
            0x00 => buf.extend_from_slice(b"\\0"),
            0x1E => buf.extend_from_slice(b"\\1E"),
            0x1F => buf.extend_from_slice(b"\\1F"),
            other => buf.push(other),
        }
    }
    buf.push(0x1F); // field terminator (ASCII US byte, but used inversely — see ChainContent doc)
}

/// Result of `verify_chain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Chain is intact across all rows checked.
    Intact { rows_checked: u64 },
    /// One or more rows fail to chain. First broken row is reported.
    Broken {
        rows_checked: u64,
        first_broken_seq: u64,
        first_broken_transaction_id: String,
        expected: String,
        actual: String,
    },
    /// Verification could not be completed (missing key, unreachable storage,
    /// retired key not on disk, etc.). Distinct from `Broken` — callers map
    /// this to exit code 2.
    CannotVerify { reason: String },
}

/// Process exit code for `sysknife audit verify`.
///
/// `0` intact, `1` broken, `2` cannot-verify. The split between 1 and 2
/// matters: a CI pipeline expecting 0 or 1 must not silently pass on a
/// missing key file.
pub fn outcome_to_exit_code(outcome: &VerifyOutcome) -> i32 {
    match outcome {
        VerifyOutcome::Intact { .. } => 0,
        VerifyOutcome::Broken { .. } => 1,
        VerifyOutcome::CannotVerify { .. } => 2,
    }
}

/// One row's worth of chain data, as fetched from the store.
#[derive(Debug, Clone)]
pub struct ChainRow {
    pub seq: u64,
    pub key_id: String,
    pub transaction_id: String,
    pub request_id: String,
    pub request_hash: String,
    pub action_name: String,
    pub risk_level: RiskLevel,
    pub summary: String,
    pub approval_id: Option<String>,
    pub warnings_json: String,
    pub created_at: String,
    pub prev_chain_hash: String,
    pub chain_hash: String,
}

/// Verify a chain using the daemon's key. Verification uses the **public** key
/// (so it proves, but cannot forge) and also asserts every row was written
/// under this key generation (`key_id`).
pub fn verify_chain(key: &AuditKey, rows: &[ChainRow]) -> VerifyOutcome {
    verify_rows(&key.verifying_key(), Some(key.key_id()), rows)
}

/// Verify a chain with only the hex-encoded Ed25519 **public** key. This is the
/// auditor / aggregator path: it proves the chain without the private key and
/// cannot be used to forge entries. `key_id` is not checked — the public key
/// itself identifies the signer.
pub fn verify_chain_with_pubkey(verifying_key_hex: &str, rows: &[ChainRow]) -> VerifyOutcome {
    match parse_verifying_key(verifying_key_hex) {
        Some(vk) => verify_rows(&vk, None, rows),
        None => VerifyOutcome::CannotVerify {
            reason: format!(
                "invalid public key hex ({} chars); expected 64 hex chars of a \
                 32-byte Ed25519 public key",
                verifying_key_hex.len()
            ),
        },
    }
}

fn parse_verifying_key(hex_str: &str) -> Option<VerifyingKey> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Verify a stored hex signature over a row's message. Any malformed signature
/// (bad hex, wrong length, invalid point) is a failed check, never a panic.
fn signature_ok(vk: &VerifyingKey, msg: &[u8], sig_hex: &str) -> bool {
    let Ok(bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(arr): Result<[u8; 64], _> = bytes.try_into() else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(&arr)).is_ok()
}

/// Walk `rows` in seq order, verifying each row's signature with `vk` and its
/// `prev_chain_hash` linkage. Returns the first break (or `Intact`). When
/// `expect_key_id` is `Some`, every row must carry that `key_id`.
fn verify_rows(vk: &VerifyingKey, expect_key_id: Option<&str>, rows: &[ChainRow]) -> VerifyOutcome {
    let mut last_hash = String::new();
    let mut rows_checked = 0u64;
    for row in rows {
        if let Some(kid) = expect_key_id {
            if row.key_id != kid {
                return VerifyOutcome::CannotVerify {
                    reason: format!(
                        "row seq={} uses key_id={:?} but only {:?} is loaded; \
                         epoch keys not yet supported",
                        row.seq, row.key_id, kid
                    ),
                };
            }
        }
        if row.prev_chain_hash != last_hash {
            return VerifyOutcome::Broken {
                rows_checked,
                first_broken_seq: row.seq,
                first_broken_transaction_id: row.transaction_id.clone(),
                expected: format!("prev_chain_hash={last_hash}"),
                actual: format!("prev_chain_hash={}", row.prev_chain_hash),
            };
        }
        let content = ChainContent {
            seq: row.seq,
            key_id: &row.key_id,
            transaction_id: &row.transaction_id,
            request_id: &row.request_id,
            request_hash: &row.request_hash,
            action_name: &row.action_name,
            risk_level: row.risk_level,
            summary: &row.summary,
            approval_id: row.approval_id.as_deref(),
            warnings_json: &row.warnings_json,
            created_at: &row.created_at,
        };
        let msg = chain_message(&content, &row.prev_chain_hash);
        if !signature_ok(vk, &msg, &row.chain_hash) {
            return VerifyOutcome::Broken {
                rows_checked,
                first_broken_seq: row.seq,
                first_broken_transaction_id: row.transaction_id.clone(),
                expected: "valid ed25519 signature".to_string(),
                actual: row.chain_hash.clone(),
            };
        }
        last_hash = row.chain_hash.clone();
        rows_checked += 1;
    }
    VerifyOutcome::Intact { rows_checked }
}

// ── Signed checkpoints (external anchoring / tail-truncation detection) ──────

/// A signed commitment to the chain tip at a point in time. Periodically
/// emitted and anchored to an independent, append-only sink (a separate
/// database, a WORM store, or an RFC 3161 timestamp) so that a later attempt to
/// rewrite or **truncate** the local chain is detectable: the anchored
/// `(seq, chain_tip)` can no longer be reproduced from the shortened chain.
///
/// This is the Certificate-Transparency "signed checkpoint" idiom. The
/// signature is Ed25519 over the canonical `(seq, chain_tip, created_at)`, so
/// an auditor verifies it with only the public key.
///
/// A `Checkpoint` value carries no validity guarantee on its own: validity is
/// established solely by [`verify_checkpoints`] under the public key. A
/// checkpoint loaded from a sink is untrusted input until verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// `seq` of the chain tip this checkpoint commits to (the last row at
    /// emit time).
    pub seq: u64,
    /// `chain_hash` of the row at `seq` (the committed chain tip).
    pub chain_tip: String,
    /// RFC 3339 timestamp when the checkpoint was signed.
    pub created_at: String,
    /// Hex Ed25519 signature over `canonical(seq, chain_tip, created_at)`.
    pub signature: String,
}

/// Canonical message signed into a checkpoint. Reuses the prefix-free field
/// framing so the encoding is unambiguous and stable across backends.
fn checkpoint_message(seq: u64, chain_tip: &str, created_at: &str) -> Vec<u8> {
    // Leading domain tag: separates checkpoint signatures from row signatures
    // (see `chain_message`) so the two contexts can never cross-verify.
    let mut buf = b"sysknife-checkpoint-v1\x1f".to_vec();
    push_field(&mut buf, "seq", &seq.to_string());
    push_field(&mut buf, "chain_tip", chain_tip);
    push_field(&mut buf, "created_at", created_at);
    buf
}

impl AuditKey {
    /// Sign a checkpoint committing to `(seq, chain_tip)` at `created_at`.
    pub fn sign_checkpoint(&self, seq: u64, chain_tip: &str, created_at: &str) -> Checkpoint {
        let sig = self
            .signing
            .sign(&checkpoint_message(seq, chain_tip, created_at));
        Checkpoint {
            seq,
            chain_tip: chain_tip.to_string(),
            created_at: created_at.to_string(),
            signature: hex::encode(sig.to_bytes()),
        }
    }
}

/// Result of checking anchored checkpoints against the current chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointOutcome {
    /// Every checkpoint's signature is valid and its committed tip is still
    /// present in the chain at the committed `seq`.
    Consistent { checkpoints_checked: u64 },
    /// A checkpoint signature failed to verify under the public key.
    BadSignature { seq: u64 },
    /// A checkpoint commits to a `seq` no longer present in the chain — the
    /// chain has been **truncated** below a previously anchored tip.
    Truncated {
        checkpoint_seq: u64,
        current_max_seq: u64,
    },
    /// A checkpoint's committed `chain_tip` does not match the chain's
    /// `chain_hash` at that `seq` — the chain was **rewritten**.
    TipMismatch {
        seq: u64,
        anchored: String,
        actual: String,
    },
    /// Could not verify (e.g. malformed public key).
    CannotVerify { reason: String },
}

/// Verify anchored `checkpoints` against `rows` (the current chain) with the
/// hex **public** key. Detects truncation (a checkpoint seq no longer in the
/// chain) and rewrite (tip mismatch at a checkpoint seq). `rows` must be in
/// seq order. This is the anti-root guarantee: a host attacker who shortens or
/// edits the local chain cannot reproduce a previously anchored signed tip.
pub fn verify_checkpoints(
    verifying_key_hex: &str,
    rows: &[ChainRow],
    checkpoints: &[Checkpoint],
) -> CheckpointOutcome {
    let vk = match parse_verifying_key(verifying_key_hex) {
        Some(vk) => vk,
        None => {
            return CheckpointOutcome::CannotVerify {
                reason: format!("invalid public key hex ({} chars)", verifying_key_hex.len()),
            };
        }
    };
    let current_max_seq = rows.iter().map(|r| r.seq).max().unwrap_or(0);
    let mut checked = 0u64;
    for cp in checkpoints {
        let msg = checkpoint_message(cp.seq, &cp.chain_tip, &cp.created_at);
        if !signature_ok(&vk, &msg, &cp.signature) {
            return CheckpointOutcome::BadSignature { seq: cp.seq };
        }
        match rows.iter().find(|r| r.seq == cp.seq) {
            Some(row) if row.chain_hash == cp.chain_tip => {}
            Some(row) => {
                return CheckpointOutcome::TipMismatch {
                    seq: cp.seq,
                    anchored: cp.chain_tip.clone(),
                    actual: row.chain_hash.clone(),
                };
            }
            None => {
                return CheckpointOutcome::Truncated {
                    checkpoint_seq: cp.seq,
                    current_max_seq,
                };
            }
        }
        checked += 1;
    }
    CheckpointOutcome::Consistent {
        checkpoints_checked: checked,
    }
}

/// Process exit code for `sysknife audit checkpoint` verification, mirroring
/// [`outcome_to_exit_code`]: `0` consistent, `1` a detected tamper (bad
/// signature / truncation / rewrite), `2` cannot-verify (e.g. malformed public
/// key). The 1-vs-2 split matters for CI exactly as it does for chain verify.
pub fn checkpoint_outcome_to_exit_code(outcome: &CheckpointOutcome) -> i32 {
    match outcome {
        CheckpointOutcome::Consistent { .. } => 0,
        CheckpointOutcome::BadSignature { .. }
        | CheckpointOutcome::Truncated { .. }
        | CheckpointOutcome::TipMismatch { .. } => 1,
        CheckpointOutcome::CannotVerify { .. } => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> AuditKey {
        AuditKey::from_bytes(vec![0x42; 32])
    }

    fn sample_content<'a>(seq: u64, txid: &'a str) -> ChainContent<'a> {
        ChainContent {
            seq,
            key_id: CURRENT_KEY_ID,
            transaction_id: txid,
            request_id: "req-1",
            request_hash: "hash-abc",
            action_name: "UpdateSystem",
            risk_level: RiskLevel::High,
            summary: "Upgrade",
            approval_id: None,
            warnings_json: "[]",
            created_at: "2026-04-24T12:00:00Z",
        }
    }

    // ── chain_hash determinism + linkage ──────────────────────────────────

    #[test]
    fn same_inputs_yield_same_hash() {
        let key = fixed_key();
        let h1 = key.chain_hash(&sample_content(1, "txa"), "");
        let h2 = key.chain_hash(&sample_content(1, "txa"), "");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), HASH_HEX_LEN);
    }

    #[test]
    fn different_seq_yields_different_hash() {
        let key = fixed_key();
        let h1 = key.chain_hash(&sample_content(1, "txa"), "");
        let h2 = key.chain_hash(&sample_content(2, "txa"), "");
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_prev_hash_yields_different_hash() {
        let key = fixed_key();
        let h1 = key.chain_hash(&sample_content(1, "txa"), "");
        let h2 = key.chain_hash(&sample_content(1, "txa"), "deadbeef");
        assert_ne!(h1, h2);
    }

    #[test]
    fn different_keys_yield_different_hashes() {
        let key1 = AuditKey::from_bytes(vec![0x01; 32]);
        let key2 = AuditKey::from_bytes(vec![0x02; 32]);
        let h1 = key1.chain_hash(&sample_content(1, "txa"), "");
        let h2 = key2.chain_hash(&sample_content(1, "txa"), "");
        assert_ne!(h1, h2);
    }

    // ── canonical encoding stability ──────────────────────────────────────

    #[test]
    fn canonical_bytes_have_stable_field_order() {
        let c = sample_content(1, "txa");
        let bytes = c.canonical_bytes();
        let s = String::from_utf8_lossy(&bytes);
        // Tags must appear in a fixed order.
        let order = [
            "seq",
            "key_id",
            "transaction_id",
            "request_id",
            "request_hash",
            "action_name",
            "risk_level",
            "summary",
            "approval_id",
            "warnings_json",
            "created_at",
        ];
        let mut last_idx = 0;
        for tag in order {
            let idx = s.find(tag).unwrap_or_else(|| panic!("missing {tag}"));
            assert!(idx >= last_idx, "{tag} out of order");
            last_idx = idx;
        }
    }

    #[test]
    fn nul_bytes_in_field_value_are_escaped() {
        let mut c = sample_content(1, "txa");
        let summary = "before\0after";
        c.summary = summary;
        let bytes = c.canonical_bytes();
        // Raw NUL must NOT appear; escape sequence must.
        assert!(!bytes.contains(&0x00));
        assert!(String::from_utf8_lossy(&bytes).contains("before\\0after"));
    }

    /// Backslash-NUL collision regression: an attacker who could craft a
    /// row with `summary = "before\\0after"` (literal backslash + zero) must
    /// NOT produce the same canonical bytes as one with raw `\x00`. Without
    /// the `\\` → `\\\\` escape, the two collide and the attacker can
    /// substitute one for the other while the chain hash matches.
    #[test]
    fn literal_backslash_zero_does_not_collide_with_raw_nul_escape() {
        let mut a = sample_content(1, "txa");
        a.summary = "before\\0after"; // literal backslash + '0'
        let mut b = sample_content(1, "txa");
        b.summary = "before\0after"; // raw NUL
        assert_ne!(
            a.canonical_bytes(),
            b.canonical_bytes(),
            "backslash escape must run before NUL escape to prevent collision"
        );
    }

    fn key_for_collision_test() -> AuditKey {
        AuditKey::from_bytes(vec![0xab; 32])
    }

    #[test]
    fn literal_backslash_zero_chain_hash_differs_from_raw_nul() {
        let key = key_for_collision_test();
        let mut a = sample_content(1, "txa");
        a.summary = "before\\0after";
        let mut b = sample_content(1, "txa");
        b.summary = "before\0after";
        assert_ne!(
            key.chain_hash(&a, ""),
            key.chain_hash(&b, ""),
            "chain signature must distinguish escape from raw byte"
        );
    }

    // ── verify_chain ──────────────────────────────────────────────────────

    fn build_chain(key: &AuditKey, count: usize) -> Vec<ChainRow> {
        let mut rows = Vec::with_capacity(count);
        let mut prev = String::new();
        for i in 0..count {
            let seq = (i + 1) as u64;
            let txid = format!("tx{i}");
            let content = sample_content(seq, &txid);
            let hash = key.chain_hash(&content, &prev);
            rows.push(ChainRow {
                seq,
                key_id: content.key_id.to_string(),
                transaction_id: content.transaction_id.to_string(),
                request_id: content.request_id.to_string(),
                request_hash: content.request_hash.to_string(),
                action_name: content.action_name.to_string(),
                risk_level: content.risk_level,
                summary: content.summary.to_string(),
                approval_id: content.approval_id.map(str::to_string),
                warnings_json: content.warnings_json.to_string(),
                created_at: content.created_at.to_string(),
                prev_chain_hash: prev.clone(),
                chain_hash: hash.clone(),
            });
            prev = hash;
        }
        rows
    }

    #[test]
    fn intact_chain_verifies() {
        let key = fixed_key();
        let rows = build_chain(&key, 5);
        let outcome = verify_chain(&key, &rows);
        assert_eq!(outcome, VerifyOutcome::Intact { rows_checked: 5 });
        assert_eq!(outcome_to_exit_code(&outcome), 0);
    }

    #[test]
    fn empty_chain_verifies() {
        let key = fixed_key();
        let outcome = verify_chain(&key, &[]);
        assert_eq!(outcome, VerifyOutcome::Intact { rows_checked: 0 });
    }

    #[test]
    fn tampered_summary_breaks_chain_at_first_offending_row() {
        let key = fixed_key();
        let mut rows = build_chain(&key, 3);
        // Mutate summary on row 1 (seq=2). Hash mismatch should be detected.
        rows[1].summary = "TAMPERED".to_string();
        let outcome = verify_chain(&key, &rows);
        match outcome {
            VerifyOutcome::Broken {
                first_broken_seq, ..
            } => assert_eq!(first_broken_seq, 2),
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[test]
    fn deleted_middle_row_breaks_chain_via_prev_hash_mismatch() {
        let key = fixed_key();
        let mut rows = build_chain(&key, 4);
        // Remove row at seq=2 entirely. Row 3's prev_chain_hash now mismatches.
        rows.remove(1);
        let outcome = verify_chain(&key, &rows);
        match outcome {
            VerifyOutcome::Broken {
                first_broken_seq, ..
            } => assert_eq!(
                first_broken_seq, 3,
                "first broken row is the one whose prev_hash refers to deleted row"
            ),
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[test]
    fn inserted_forged_row_breaks_chain() {
        // Counterpart to `deleted_middle_row_…`. An attacker who managed to
        // insert a fabricated row between two genuine ones still cannot
        // produce a `chain_hash` that links the insertion back to the prior
        // row's hash, so verification must flag the forgery at the inserted
        // row (or at the immediately following genuine row whose
        // `prev_chain_hash` no longer matches its real predecessor).
        let key = fixed_key();
        let mut rows = build_chain(&key, 3);

        // Splice in a new row between seq=1 and seq=2 with a fabricated hash.
        let forged = ChainRow {
            seq: 2,
            key_id: CURRENT_KEY_ID.to_string(),
            transaction_id: "tx-forged".to_string(),
            request_id: "req-forged".to_string(),
            request_hash: "hash-forged".to_string(),
            action_name: "InstallFlatpak".to_string(),
            risk_level: RiskLevel::Medium,
            summary: "Forged row".to_string(),
            approval_id: None,
            warnings_json: "[]".to_string(),
            created_at: "2026-04-25T13:00:00Z".to_string(),
            // Plausible prev_chain_hash chosen to look intact at boundary.
            prev_chain_hash: rows[0].chain_hash.clone(),
            // Not a valid signature; verification must reject this.
            chain_hash: "0".repeat(HASH_HEX_LEN),
        };

        // Renumber the genuine seq=2/3 rows so seq is still 1..=4.
        let mut rest: Vec<ChainRow> = rows.split_off(1);
        for r in rest.iter_mut() {
            r.seq += 1;
        }
        rows.push(forged);
        rows.extend(rest);

        let outcome = verify_chain(&key, &rows);
        match outcome {
            VerifyOutcome::Broken {
                first_broken_seq, ..
            } => assert!(
                first_broken_seq == 2 || first_broken_seq == 3,
                "verifier must flag the inserted row or the row that follows it (got {first_broken_seq})"
            ),
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    // ── Ed25519 public-key verification / non-repudiation ─────────────────

    #[test]
    fn signature_verifies_under_exported_public_key() {
        // The auditor path: verify with only the public key.
        let key = fixed_key();
        let rows = build_chain(&key, 4);
        let outcome = verify_chain_with_pubkey(&key.verifying_key_hex(), &rows);
        assert_eq!(outcome, VerifyOutcome::Intact { rows_checked: 4 });
    }

    #[test]
    fn foreign_public_key_cannot_validate_chain() {
        // Non-repudiation: a different keypair's public key neither validates
        // the chain nor (by construction) could forge it. This is the property
        // the old symmetric HMAC could not provide.
        let signer = AuditKey::from_bytes(vec![0x11; 32]);
        let rows = build_chain(&signer, 3);
        let other = AuditKey::from_bytes(vec![0x22; 32]);
        let outcome = verify_chain_with_pubkey(&other.verifying_key_hex(), &rows);
        assert!(matches!(
            outcome,
            VerifyOutcome::Broken {
                first_broken_seq: 1,
                ..
            }
        ));
    }

    #[test]
    fn verifying_key_hex_is_a_32_byte_public_key() {
        let key = fixed_key();
        let vk_hex = key.verifying_key_hex();
        assert_eq!(
            vk_hex.len(),
            64,
            "32-byte ed25519 public key = 64 hex chars"
        );
        assert!(hex::decode(&vk_hex).is_ok());
    }

    #[test]
    fn malformed_signature_hex_is_broken_not_panic() {
        let key = fixed_key();
        let mut rows = build_chain(&key, 2);
        rows[0].chain_hash = "not-valid-hex!!".to_string();
        let outcome = verify_chain(&key, &rows);
        assert!(matches!(
            outcome,
            VerifyOutcome::Broken {
                first_broken_seq: 1,
                ..
            }
        ));
    }

    #[test]
    fn bad_public_key_hex_yields_cannot_verify() {
        let key = fixed_key();
        let rows = build_chain(&key, 1);
        let outcome = verify_chain_with_pubkey("zz", &rows);
        assert!(matches!(outcome, VerifyOutcome::CannotVerify { .. }));
    }

    #[test]
    fn load_or_generate_writes_public_key_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-key");
        let key = AuditKey::load_or_generate(&path).unwrap();
        let pub_path = dir.path().join("audit-key.pub");
        assert!(pub_path.exists(), "public key sidecar must be written");
        let pub_hex = std::fs::read_to_string(&pub_path).unwrap();
        assert_eq!(pub_hex.trim(), key.verifying_key_hex());
    }

    #[test]
    fn wrong_key_id_yields_cannot_verify() {
        let key = fixed_key();
        let mut rows = build_chain(&key, 2);
        rows[0].key_id = "v99".to_string();
        let outcome = verify_chain(&key, &rows);
        assert!(matches!(outcome, VerifyOutcome::CannotVerify { .. }));
        assert_eq!(outcome_to_exit_code(&outcome), 2);
    }

    #[test]
    fn exit_code_for_each_outcome() {
        assert_eq!(
            outcome_to_exit_code(&VerifyOutcome::Intact { rows_checked: 0 }),
            0
        );
        assert_eq!(
            outcome_to_exit_code(&VerifyOutcome::Broken {
                rows_checked: 0,
                first_broken_seq: 1,
                first_broken_transaction_id: String::new(),
                expected: String::new(),
                actual: String::new(),
            }),
            1
        );
        assert_eq!(
            outcome_to_exit_code(&VerifyOutcome::CannotVerify {
                reason: String::new()
            }),
            2
        );
    }

    // ── AuditKey file management ──────────────────────────────────────────

    #[test]
    fn load_or_generate_creates_with_0600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-key");
        let _key = AuditKey::load_or_generate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn load_or_generate_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-key");
        let key1_bytes = {
            let _ = AuditKey::load_or_generate(&path).unwrap();
            std::fs::read(&path).unwrap()
        };
        let _ = AuditKey::load_or_generate(&path).unwrap();
        let key2_bytes = std::fs::read(&path).unwrap();
        assert_eq!(key1_bytes, key2_bytes, "second load must not regenerate");
    }

    #[test]
    fn rejects_world_readable_key_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-key");
        std::fs::write(&path, vec![0u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let result = AuditKey::load_or_generate(&path);
        assert!(matches!(
            result,
            Err(AuditKeyError::UnsafePermissions { .. })
        ));
    }

    #[test]
    fn rejects_short_key_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-key");
        std::fs::write(&path, vec![0u8; 8]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let result = AuditKey::load_or_generate(&path);
        assert!(matches!(result, Err(AuditKeyError::KeyTooShort { .. })));
    }

    // ── Debug redaction (HI-17 secret hygiene) ────────────────────────────

    /// `Debug` must never expose the Ed25519 private key material, neither raw bytes,
    /// nor their hex encoding. A derived `Debug` would dump the bytes the
    /// moment anyone wrote `tracing::debug!("{key:?}")`.
    #[test]
    fn debug_redacts_key_bytes_and_their_hex_encoding() {
        // Use a distinctive byte pattern so accidental leaks are obvious.
        let raw = (0u8..32).collect::<Vec<u8>>();
        let key = AuditKey::from_bytes(raw.clone());
        let dbg = format!("{key:?}");

        assert!(
            dbg.contains("redacted"),
            "Debug output must contain the literal 'redacted' marker, got: {dbg}"
        );

        // Hex encoding of the bytes must NOT appear, in either case.
        let hex_lower = hex::encode(&raw);
        let hex_upper = hex::encode_upper(&raw);
        assert!(
            !dbg.contains(&hex_lower),
            "Debug output leaks lowercase hex of key bytes: {dbg}"
        );
        assert!(
            !dbg.contains(&hex_upper),
            "Debug output leaks uppercase hex of key bytes: {dbg}"
        );

        // Each individual byte's two-hex-char form must also be absent. This
        // catches the case where a future change splits the bytes across the
        // formatter and prints them piecewise.
        for b in &raw {
            let pair = format!("{b:02x}");
            // 1-byte values 0x00..0x0f render as "00".."0f" — too short to
            // assert against safely (collides with key_id "v1" etc.). Only
            // check 2-char forms that cannot incidentally match the rest of
            // the Debug output.
            if *b >= 0x10 && pair != "1e" && pair != "1f" {
                assert!(
                    !dbg.contains(&pair),
                    "Debug output leaks byte {b:#04x} as {pair:?}: {dbg}"
                );
            }
        }
    }

    /// Operators triaging a chain break need to know which key generation
    /// produced a row. `key_id` is not secret and must remain visible.
    #[test]
    fn debug_preserves_key_id() {
        let key = AuditKey::from_bytes(vec![0xff; 32]);
        let dbg = format!("{key:?}");
        assert!(
            dbg.contains("key_id"),
            "Debug output must label the key_id field: {dbg}"
        );
        assert!(
            dbg.contains(CURRENT_KEY_ID),
            "Debug output must contain the key_id value {CURRENT_KEY_ID:?}: {dbg}"
        );
    }

    // ── signed checkpoints (anti-truncation / anti-rewrite) ───────────────

    #[test]
    fn checkpoint_consistent_with_intact_chain() {
        let key = fixed_key();
        let rows = build_chain(&key, 5);
        let cp = key.sign_checkpoint(3, &rows[2].chain_hash, "2026-04-24T12:00:00Z");
        let outcome = verify_checkpoints(&key.verifying_key_hex(), &rows, &[cp]);
        assert_eq!(
            outcome,
            CheckpointOutcome::Consistent {
                checkpoints_checked: 1
            }
        );
    }

    #[test]
    fn checkpoint_detects_truncation() {
        let key = fixed_key();
        let full = build_chain(&key, 5);
        // Anchor a checkpoint at the tip (seq=5); later the chain is cut to 3.
        let cp = key.sign_checkpoint(5, &full[4].chain_hash, "2026-04-24T12:00:00Z");
        let truncated = &full[..3];
        let outcome = verify_checkpoints(&key.verifying_key_hex(), truncated, &[cp]);
        assert!(matches!(
            outcome,
            CheckpointOutcome::Truncated {
                checkpoint_seq: 5,
                current_max_seq: 3
            }
        ));
    }

    #[test]
    fn checkpoint_detects_rewrite() {
        let key = fixed_key();
        let mut rows = build_chain(&key, 4);
        let cp = key.sign_checkpoint(3, &rows[2].chain_hash, "2026-04-24T12:00:00Z");
        // Rewrite the row at seq=3 after the checkpoint was anchored.
        rows[2].chain_hash = "0".repeat(HASH_HEX_LEN);
        let outcome = verify_checkpoints(&key.verifying_key_hex(), &rows, &[cp]);
        assert!(matches!(
            outcome,
            CheckpointOutcome::TipMismatch { seq: 3, .. }
        ));
    }

    #[test]
    fn checkpoint_bad_signature_detected() {
        let key = fixed_key();
        let rows = build_chain(&key, 3);
        let mut cp = key.sign_checkpoint(2, &rows[1].chain_hash, "2026-04-24T12:00:00Z");
        cp.signature = "0".repeat(HASH_HEX_LEN); // not a valid signature
        let outcome = verify_checkpoints(&key.verifying_key_hex(), &rows, &[cp]);
        assert!(matches!(
            outcome,
            CheckpointOutcome::BadSignature { seq: 2 }
        ));
    }

    #[test]
    fn checkpoint_foreign_key_rejected() {
        // A checkpoint signed by one key must not verify under another key.
        let signer = AuditKey::from_bytes(vec![0x11; 32]);
        let rows = build_chain(&signer, 3);
        let cp = signer.sign_checkpoint(2, &rows[1].chain_hash, "2026-04-24T12:00:00Z");
        let other = AuditKey::from_bytes(vec![0x22; 32]);
        let outcome = verify_checkpoints(&other.verifying_key_hex(), &rows, &[cp]);
        assert!(matches!(
            outcome,
            CheckpointOutcome::BadSignature { seq: 2 }
        ));
    }

    #[test]
    fn pubkey_verify_detects_tampered_middle_row() {
        // The core auditor claim: with only the public key, a mutated field in
        // a non-first row is detected at that exact seq.
        let key = fixed_key();
        let mut rows = build_chain(&key, 4);
        rows[2].summary = "TAMPERED".to_string();
        let outcome = verify_chain_with_pubkey(&key.verifying_key_hex(), &rows);
        assert!(matches!(
            outcome,
            VerifyOutcome::Broken {
                first_broken_seq: 3,
                ..
            }
        ));
    }

    #[test]
    fn multiple_checkpoints_all_consistent() {
        let key = fixed_key();
        let rows = build_chain(&key, 5);
        let cps = vec![
            key.sign_checkpoint(2, &rows[1].chain_hash, "2026-04-24T12:00:00Z"),
            key.sign_checkpoint(3, &rows[2].chain_hash, "2026-04-24T12:05:00Z"),
            key.sign_checkpoint(5, &rows[4].chain_hash, "2026-04-24T12:10:00Z"),
        ];
        assert_eq!(
            verify_checkpoints(&key.verifying_key_hex(), &rows, &cps),
            CheckpointOutcome::Consistent {
                checkpoints_checked: 3
            }
        );
    }

    #[test]
    fn middle_checkpoint_failure_is_reported() {
        // Earlier-consistent checkpoints must not mask a later failure.
        let key = fixed_key();
        let mut rows = build_chain(&key, 5);
        let cps = vec![
            key.sign_checkpoint(2, &rows[1].chain_hash, "2026-04-24T12:00:00Z"),
            key.sign_checkpoint(3, &rows[2].chain_hash, "2026-04-24T12:05:00Z"),
            key.sign_checkpoint(5, &rows[4].chain_hash, "2026-04-24T12:10:00Z"),
        ];
        rows[2].chain_hash = "0".repeat(HASH_HEX_LEN); // rewrite what cp #2 commits to
        assert!(matches!(
            verify_checkpoints(&key.verifying_key_hex(), &rows, &cps),
            CheckpointOutcome::TipMismatch { seq: 3, .. }
        ));
    }

    #[test]
    fn checkpoint_created_at_is_signed() {
        // created_at is inside the signed message: backdating invalidates it.
        let key = fixed_key();
        let rows = build_chain(&key, 3);
        let mut cp = key.sign_checkpoint(3, &rows[2].chain_hash, "2026-04-24T12:00:00Z");
        cp.created_at = "2020-01-01T00:00:00Z".to_string();
        assert!(matches!(
            verify_checkpoints(&key.verifying_key_hex(), &rows, &[cp]),
            CheckpointOutcome::BadSignature { .. }
        ));
    }

    #[test]
    fn checkpoint_seq_is_signed() {
        // seq is inside the signed message: moving it invalidates the signature.
        let key = fixed_key();
        let rows = build_chain(&key, 3);
        let mut cp = key.sign_checkpoint(3, &rows[2].chain_hash, "2026-04-24T12:00:00Z");
        cp.seq = 2;
        assert!(matches!(
            verify_checkpoints(&key.verifying_key_hex(), &rows, &[cp]),
            CheckpointOutcome::BadSignature { seq: 2 }
        ));
    }

    #[test]
    fn checkpoint_detects_full_wipe() {
        // The whole chain deleted: the anchored tip cannot be reproduced.
        let key = fixed_key();
        let full = build_chain(&key, 3);
        let cp = key.sign_checkpoint(3, &full[2].chain_hash, "2026-04-24T12:00:00Z");
        assert!(matches!(
            verify_checkpoints(&key.verifying_key_hex(), &[], &[cp]),
            CheckpointOutcome::Truncated {
                checkpoint_seq: 3,
                current_max_seq: 0
            }
        ));
    }
}
