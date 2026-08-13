//! Forward Ed25519-signed hash chain for the audit log.
//!
//! Each `transactions` row stores `chain_hash` and `prev_chain_hash` columns.
//! On insert, the daemon computes
//!
//! ```text
//! chain_hash = ed25519_sign(ROW_DOMAIN || canonical(immutable_fields) || prev_chain_hash, signing_key)
//! ```
//!
//! The `ROW_DOMAIN` prefix is **part of the signed message**, not decoration:
//! it is what stops a row signature from ever verifying as a checkpoint or
//! approval-receipt signature. An independent verifier that omits it will
//! never reproduce a valid `chain_hash`.
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
//!   execution state. Status transitions ARE chained, separately: the
//!   append-only `audit_events` table exists (created by migration v2 in
//!   `transactions.rs`) and `verify_event_chain` / `verify_event_binding`
//!   below verify it. This paragraph described that as future work long
//!   after it shipped, which is worse than saying nothing — a reader would
//!   conclude the capability is missing and either duplicate it or assume
//!   status history is unprotected.
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
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use sysknife_types::RiskLevel;
use zeroize::Zeroize;

/// Stable identifier for the current key generation. Stored in every row.
/// Tied to the schema, not the key bytes — rotation will introduce `"v2"` etc.
pub const CURRENT_KEY_ID: &str = "v1";

/// Hex-encoded length of an Ed25519 signature (64 raw bytes → 128 hex chars).
pub const HASH_HEX_LEN: usize = 128;

/// Domain-separation tags for Ed25519 signing contexts. They MUST stay distinct
/// and prefix-free so a signature made in one context can never verify in any
/// other. Enforced by the `domain_tags_are_distinct_and_prefix_free` test.
const ROW_DOMAIN: &[u8] = b"sysknife-audit-row-v1\x1f";
const CHECKPOINT_DOMAIN: &[u8] = b"sysknife-checkpoint-v1\x1f";
const APPROVAL_DOMAIN: &[u8] = b"sysknife-approval-receipt-v1\x1f";
const EVENT_DOMAIN: &[u8] = b"sysknife-audit-event-v1\x1f";

/// Row encoding written before the caller-identity migration: no
/// `caller_role`, no `event_tip`. Still verifiable — see [`ChainIdentity`].
pub const CHAIN_VERSION_LEGACY: u32 = 1;
/// Row encoding that added `caller_role` and `event_tip`.
///
/// This is a **stable literal, never an alias for the newest version**. The v2
/// encoder signs this value, and `ChainRow::identity` dispatches stored rows
/// against it. Point either at `CHAIN_VERSION_CURRENT` and the next encoding
/// bump silently re-encodes every v2 row on disk, breaking audit logs while the
/// unit suite stays green, because in-memory tests sign and verify under the
/// same constant. `a_row_written_by_the_previous_release_still_verifies` is the
/// golden vector that notices.
pub const CHAIN_VERSION_V2: u32 = 2;
/// Row encoding that added `caller_principal` on top of v2, so a row names the
/// account that asked, not only its role class.
///
/// A stable literal for the same reason [`CHAIN_VERSION_V2`] is one: the v3
/// encoder signs this value and `ChainRow::identity` dispatches stored v3 rows
/// against it, so it must not move when a v4 encoding arrives.
/// `a_v3_row_on_disk_still_verifies` is the golden vector that notices if it does.
pub const CHAIN_VERSION_V3: u32 = 3;
/// The encoding this binary *writes*. Always an alias for the newest versioned
/// constant, never used to encode or dispatch a specific generation.
///
/// Kept distinct from the per-version literals because those two jobs pull in
/// opposite directions: the writer must move with each new encoding, while every
/// stored generation must keep being reproduced byte for byte forever.
pub const CHAIN_VERSION_CURRENT: u32 = CHAIN_VERSION_V3;

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

    /// Derive the bearer receipt for one immutable preview. The signature is
    /// deterministic, so a failed response delivery can be retried without
    /// storing plaintext bearer credentials in the database.
    pub fn approval_receipt(&self, transaction_id: &str, request_hash: &str) -> String {
        // Frame both fields through `push_field` (the same escaping used for
        // chain rows) so the signed message is injective in
        // (transaction_id, request_hash). Raw concatenation with a bare 0x1F
        // would alias distinct inputs if either field ever contained 0x1F;
        // escaping removes that dependency on the callers' value shapes.
        let mut message = APPROVAL_DOMAIN.to_vec();
        push_field(&mut message, "txid", transaction_id);
        push_field(&mut message, "reqhash", request_hash);
        hex::encode(self.signing.sign(&message).to_bytes())
    }

    /// Chain-stored SHA-256 commitment to the deterministic approval receipt.
    pub fn approval_commitment(&self, transaction_id: &str, request_hash: &str) -> String {
        approval_receipt_digest(&self.approval_receipt(transaction_id, request_hash))
    }
}

pub fn approval_receipt_digest(receipt: &str) -> String {
    hex::encode(Sha256::digest(receipt.as_bytes()))
}

/// Message signed for a row: `ROW_DOMAIN || canonical(content) || prev_chain_hash`.
///
/// The leading domain tag separates row signatures from checkpoint signatures
/// so a signature produced in one context can never verify in the other, even
/// if the framed fields were ever to overlap.
fn chain_message(content: &ChainContent, prev_chain_hash: &str) -> Vec<u8> {
    let mut msg = ROW_DOMAIN.to_vec();
    msg.extend_from_slice(&content.canonical_bytes());
    msg.extend_from_slice(prev_chain_hash.as_bytes());
    msg
}

/// Resolve the audit key file path: `$SYSKNIFE_AUDIT_KEY_PATH` if set,
/// otherwise `<db_dir>/audit-key` (sibling of the database). This is the single
/// definition of the key-location precedence documented in the module header;
/// the CLI verify/checkpoint paths resolve through it so they always agree with
/// the daemon on where the key lives.
pub fn resolve_audit_key_path(db_path: &Path) -> PathBuf {
    std::env::var("SYSKNIFE_AUDIT_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            db_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join("audit-key")
        })
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
/// Which generation of the canonical row encoding a row was signed under.
///
/// # Why this is an enum and not two `Option` fields
///
/// Adding a field to [`ChainContent`] changes the signed message, so every row
/// written before the change would re-encode differently and report as
/// `Broken`. Chains already exist in the field, and "delete your audit log to
/// upgrade" is not an acceptable migration for an audit log. The stored
/// `chain_version` column therefore selects the encoding **per row**: legacy
/// rows keep the exact bytes they were signed over, new rows carry the
/// identity fields.
///
/// A downgrade is not a hiding place. Rewriting a `V2` row as `LegacyV1` (to
/// erase `caller_role`) makes verification re-encode it without the identity
/// fields, so the stored signature — made over the `V2` message — no longer
/// verifies and the row reports as `Broken`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainIdentity<'a> {
    /// `chain_version = 1`. Written before the identity migration.
    LegacyV1,
    /// `chain_version = 2`. Binds the row to the authenticated caller and to
    /// the approval-event chain tip at insert time.
    V2 {
        /// Role the daemon resolved for the connection that requested this
        /// action (`SO_PEERCRED` for Unix sockets, token for vsock). Signing it
        /// lets an auditor answer which privilege tier asked; naming the account
        /// is v3's `caller_principal`.
        caller_role: &'a str,
        /// `chain_hash` of the last [`EventRow`] at insert time, or `""` when
        /// the event chain is empty. This is the cross-chain binding: because
        /// checkpoints anchor the *transaction* chain tip, a committed
        /// `event_tip` transitively anchors the event chain, so deleting
        /// approval events below it becomes detectable.
        event_tip: &'a str,
    },
    /// `chain_version = 3`. Everything v2 binds, plus the individual account.
    ///
    /// v2 answers "an Admin did this". On a host with two members of
    /// `sysknife-admin` their signed records were indistinguishable, so the
    /// trail could not answer the first question an investigation asks. v3
    /// signs a principal as well.
    V3 {
        /// As v2.
        caller_role: &'a str,
        /// As v2.
        event_tip: &'a str,
        /// Scheme-prefixed identity of the caller, produced by
        /// [`crate::auth::CallerPrincipal`]: `uid:1000` for a Unix-socket peer
        /// whose credentials the kernel attested, `token:vsock` for a vsock
        /// connection authenticated by the pre-shared token, and
        /// `none:unattributed` when the daemon could establish neither.
        ///
        /// The scheme is signed along with the value on purpose. An auditor must
        /// be able to tell a kernel-attested account from a shared secret that
        /// any holder could have presented, and a bare string would erase that
        /// difference.
        caller_principal: &'a str,
    },
}

impl ChainIdentity<'_> {
    /// `chain_version` column value for this encoding.
    pub fn version(&self) -> u32 {
        match self {
            Self::LegacyV1 => CHAIN_VERSION_LEGACY,
            Self::V2 { .. } => CHAIN_VERSION_V2,
            Self::V3 { .. } => CHAIN_VERSION_V3,
        }
    }
}

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
    /// Signed receipt commitment for daemon-created previews. Legacy/imported
    /// rows may be `None`; serialised as empty for wire compatibility.
    pub approval_id: Option<&'a str>,
    /// JSON-canonical (sorted keys) array of warning strings.
    pub warnings_json: &'a str,
    pub created_at: &'a str,
    /// Encoding generation. See [`ChainIdentity`] for why this is per-row.
    pub identity: ChainIdentity<'a>,
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
        // Per-generation suffixes are *appended*, so a legacy row's bytes are
        // unchanged and its signature still verifies. The `chain_version` tag
        // leads each suffix, so no generation can alias another: two encodings
        // differ in a signed field, not merely in field count.
        //
        // This is an exhaustive `match`, not a sequence of `if let`s, and that
        // matters more than it looks. With `if let` chains, adding a variant and
        // forgetting its arm compiles fine and silently encodes the new
        // generation byte-identically to `LegacyV1` — signing an aliased message,
        // which is exactly what the tag is supposed to prevent. As a `match`,
        // the same omission is a compile error.
        //
        // Each arm spells its own fields out rather than sharing a helper. The
        // duplication is deliberate: a frozen encoding must be able to stay
        // frozen while a newer one changes.
        match self.identity {
            ChainIdentity::LegacyV1 => {}
            ChainIdentity::V2 {
                caller_role,
                event_tip,
            } => {
                push_field(&mut buf, "chain_version", &CHAIN_VERSION_V2.to_string());
                push_field(&mut buf, "caller_role", caller_role);
                push_field(&mut buf, "event_tip", event_tip);
            }
            ChainIdentity::V3 {
                caller_role,
                event_tip,
                caller_principal,
            } => {
                push_field(&mut buf, "chain_version", &CHAIN_VERSION_V3.to_string());
                push_field(&mut buf, "caller_role", caller_role);
                push_field(&mut buf, "event_tip", event_tip);
                push_field(&mut buf, "caller_principal", caller_principal);
            }
        }
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
    /// Which encoding this row was signed under. See [`ChainIdentity`].
    pub chain_version: u32,
    /// `NULL` for legacy rows; required for `chain_version` 2 and 3.
    pub caller_role: Option<String>,
    /// `NULL` for legacy rows; required for `chain_version` 2 and 3. May be the
    /// empty string when the event chain was empty at insert time.
    pub event_tip: Option<String>,
    /// `NULL` for rows written before the principal migration (v1 and v2);
    /// required for `chain_version = 3`. Scheme-prefixed, see
    /// [`ChainIdentity::V3`].
    pub caller_principal: Option<String>,
}

/// Why a stored row's columns do not describe a verifiable encoding.
#[derive(Debug)]
pub(crate) enum RowIdentityError {
    /// The row claims an encoding this binary does not know how to reproduce.
    /// Genuinely unverifiable, not evidence of tampering — an older binary
    /// reading a newer chain lands here.
    UnknownVersion(u32),
    /// The row claims an identity encoding (2 or 3) but is missing one of its
    /// columns. For v3 that includes a blank `caller_principal`, treated as
    /// absent: a row naming nobody must not pass for one naming an account.
    /// No message can be reconstructed, and the shape is self-contradictory,
    /// so this counts as a detected break rather than an inability to check.
    MissingField(&'static str),
}

impl ChainRow {
    /// Recover the encoding this row was signed under, so a caller can rebuild
    /// the exact message that produced `chain_hash`.
    pub(crate) fn identity(&self) -> Result<ChainIdentity<'_>, RowIdentityError> {
        match self.chain_version {
            CHAIN_VERSION_LEGACY => Ok(ChainIdentity::LegacyV1),
            CHAIN_VERSION_V2 => Ok(ChainIdentity::V2 {
                caller_role: self
                    .caller_role
                    .as_deref()
                    .ok_or(RowIdentityError::MissingField("caller_role"))?,
                event_tip: self
                    .event_tip
                    .as_deref()
                    .ok_or(RowIdentityError::MissingField("event_tip"))?,
            }),
            CHAIN_VERSION_V3 => Ok(ChainIdentity::V3 {
                caller_role: self
                    .caller_role
                    .as_deref()
                    .ok_or(RowIdentityError::MissingField("caller_role"))?,
                event_tip: self
                    .event_tip
                    .as_deref()
                    .ok_or(RowIdentityError::MissingField("event_tip"))?,
                // An empty principal is treated as absent: a v3 row must name
                // who asked, and "" names nobody. Accepting it would let a
                // blank pass for an identity.
                caller_principal: self
                    .caller_principal
                    .as_deref()
                    .filter(|p| !p.is_empty())
                    .ok_or(RowIdentityError::MissingField("caller_principal"))?,
            }),
            other => Err(RowIdentityError::UnknownVersion(other)),
        }
    }
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
        let identity = match row.identity() {
            Ok(identity) => identity,
            Err(RowIdentityError::UnknownVersion(v)) => {
                return VerifyOutcome::CannotVerify {
                    reason: format!(
                        "row seq={} declares chain_version={v}, which this binary cannot \
                         reproduce (it understands {CHAIN_VERSION_LEGACY}..={CHAIN_VERSION_CURRENT}); \
                         verify with a build at least as new as the one that wrote the chain",
                        row.seq
                    ),
                };
            }
            Err(RowIdentityError::MissingField(field)) => {
                // Report the version the row itself declares. Formatting
                // CHAIN_VERSION_CURRENT here sent an operator investigating a
                // v2 row to the wrong encoding, and got worse every time the
                // newest version moved.
                let stored = match field {
                    "caller_role" => row.caller_role.as_deref(),
                    "event_tip" => row.event_tip.as_deref(),
                    "caller_principal" => row.caller_principal.as_deref(),
                    _ => None,
                };
                return VerifyOutcome::Broken {
                    rows_checked,
                    first_broken_seq: row.seq,
                    first_broken_transaction_id: row.transaction_id.clone(),
                    expected: format!(
                        "chain_version={} row carrying a non-empty {field}",
                        row.chain_version
                    ),
                    // An empty column and an absent one send an operator to
                    // different SQL, so they must not print the same way.
                    actual: match stored {
                        None => format!("{field}=NULL"),
                        Some("") => format!("{field}='' (empty, not NULL)"),
                        Some(other) => format!("{field}={other:?}"),
                    },
                };
            }
        };
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
            identity,
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

// ── Approval-event chain ─────────────────────────────────────────────────────

/// A lifecycle event on an approval receipt.
///
/// The `transactions` chain commits to the *authorisation decision* at preview
/// time. It says nothing about whether a human ever approved, whether that
/// approval was spent, or whether it was retracted — those live in
/// `transaction_approvals`, a plain mutable table. Deleting a row from it used
/// to leave `sysknife audit verify` reporting `Intact`, so the record that an
/// approval happened was the one part of the trail an attacker could erase
/// without leaving a mark. These events are chained so that erasure breaks a
/// signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventKind {
    /// A receipt was minted for a queued transaction.
    ApprovalGranted,
    /// A receipt was spent to move a transaction into `Running`.
    ApprovalConsumed,
    /// An undelivered receipt was retracted before it could be spent.
    ApprovalRevoked,
}

impl AuditEventKind {
    /// Stored and signed spelling. Stable on the wire — changing one of these
    /// strings invalidates every event signature already written.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApprovalGranted => "approval_granted",
            Self::ApprovalConsumed => "approval_consumed",
            Self::ApprovalRevoked => "approval_revoked",
        }
    }
}

/// Immutable content of one approval event, signed into the event chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventContent<'a> {
    pub seq: u64,
    pub key_id: &'a str,
    pub kind: AuditEventKind,
    pub transaction_id: &'a str,
    /// The receipt digest the event concerns. Binds the event to the specific
    /// receipt, so swapping in a different approval's digest breaks the
    /// signature.
    pub receipt_digest: &'a str,
    pub created_at: &'a str,
}

impl EventContent<'_> {
    /// Canonical encoding, using the same prefix-free field framing as
    /// [`ChainContent::canonical_bytes`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        push_field(&mut buf, "seq", &self.seq.to_string());
        push_field(&mut buf, "key_id", self.key_id);
        push_field(&mut buf, "kind", self.kind.as_str());
        push_field(&mut buf, "transaction_id", self.transaction_id);
        push_field(&mut buf, "receipt_digest", self.receipt_digest);
        push_field(&mut buf, "created_at", self.created_at);
        buf
    }
}

fn event_message(content: &EventContent, prev_chain_hash: &str) -> Vec<u8> {
    let mut msg = EVENT_DOMAIN.to_vec();
    msg.extend_from_slice(&content.canonical_bytes());
    msg.extend_from_slice(prev_chain_hash.as_bytes());
    msg
}

impl AuditKey {
    /// Compute the event-chain signature for `content` linked to
    /// `prev_chain_hash`. Separate domain tag from rows and checkpoints, so an
    /// event signature can never be replayed as a transaction row.
    pub fn event_hash(&self, content: &EventContent, prev_chain_hash: &str) -> String {
        hex::encode(
            self.signing
                .sign(&event_message(content, prev_chain_hash))
                .to_bytes(),
        )
    }
}

/// One approval event as fetched from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub seq: u64,
    pub key_id: String,
    /// Stored spelling of an [`AuditEventKind`]. Kept as a string so an
    /// unrecognised value read from the database is a verification failure
    /// rather than a deserialisation panic.
    pub kind: String,
    pub transaction_id: String,
    pub receipt_digest: String,
    pub created_at: String,
    pub prev_chain_hash: String,
    pub chain_hash: String,
}

/// Verify the approval-event chain with the daemon's key.
pub fn verify_event_chain(key: &AuditKey, rows: &[EventRow]) -> VerifyOutcome {
    verify_event_rows(&key.verifying_key(), Some(key.key_id()), rows)
}

/// Verify the approval-event chain with only the exported public key.
pub fn verify_event_chain_with_pubkey(verifying_key_hex: &str, rows: &[EventRow]) -> VerifyOutcome {
    match parse_verifying_key(verifying_key_hex) {
        Some(vk) => verify_event_rows(&vk, None, rows),
        None => VerifyOutcome::CannotVerify {
            reason: format!(
                "invalid public key hex ({} chars); expected 64 hex chars of a \
                 32-byte Ed25519 public key",
                verifying_key_hex.len()
            ),
        },
    }
}

fn verify_event_rows(
    vk: &VerifyingKey,
    expect_key_id: Option<&str>,
    rows: &[EventRow],
) -> VerifyOutcome {
    let mut last_hash = String::new();
    let mut rows_checked = 0u64;
    for row in rows {
        if let Some(kid) = expect_key_id {
            if row.key_id != kid {
                return VerifyOutcome::CannotVerify {
                    reason: format!(
                        "event seq={} uses key_id={:?} but only {:?} is loaded; \
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
        // An unknown `kind` cannot be re-encoded, so it can never reproduce a
        // valid signature. Report it as the break it is instead of guessing.
        let Some(kind) = parse_event_kind(&row.kind) else {
            return VerifyOutcome::Broken {
                rows_checked,
                first_broken_seq: row.seq,
                first_broken_transaction_id: row.transaction_id.clone(),
                expected: "a known event kind".to_string(),
                actual: format!("kind={:?}", row.kind),
            };
        };
        let content = EventContent {
            seq: row.seq,
            key_id: &row.key_id,
            kind,
            transaction_id: &row.transaction_id,
            receipt_digest: &row.receipt_digest,
            created_at: &row.created_at,
        };
        if !signature_ok(
            vk,
            &event_message(&content, &row.prev_chain_hash),
            &row.chain_hash,
        ) {
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

fn parse_event_kind(raw: &str) -> Option<AuditEventKind> {
    // Exhaustive by construction: the match below fails to compile if a
    // variant is added without a spelling here.
    [
        AuditEventKind::ApprovalGranted,
        AuditEventKind::ApprovalConsumed,
        AuditEventKind::ApprovalRevoked,
    ]
    .into_iter()
    .find(|kind| kind.as_str() == raw)
}

/// Result of checking that the transaction chain's committed `event_tip`
/// values are still reproducible from the event chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingOutcome {
    /// Every committed tip is present in the event chain.
    Consistent { bindings_checked: u64 },
    /// A transaction row committed to an event tip that no longer exists —
    /// approval events were deleted from the end of the event chain, which the
    /// event chain walk alone cannot see.
    MissingEvent {
        transaction_seq: u64,
        event_tip: String,
    },
}

/// Check the cross-chain binding: each `chain_version = 2` transaction row
/// signs the event-chain tip as of its insert, so a later deletion of trailing
/// approval events leaves a tip that can no longer be found.
///
/// This is what extends checkpoint anchoring to the event chain for free: the
/// checkpoints commit to the transaction tip, the transaction rows commit to
/// event tips. Events appended *after* the last transaction row are still
/// unanchored until the next row is written — the same bounded tail exposure
/// the transaction chain has between checkpoints.
pub fn verify_event_binding(tx_rows: &[ChainRow], event_rows: &[EventRow]) -> BindingOutcome {
    let known: std::collections::HashSet<&str> = event_rows
        .iter()
        .map(|row| row.chain_hash.as_str())
        .collect();
    let mut bindings_checked = 0u64;
    for row in tx_rows {
        let Some(tip) = row.event_tip.as_deref() else {
            continue;
        };
        if tip.is_empty() {
            continue;
        }
        if !known.contains(tip) {
            return BindingOutcome::MissingEvent {
                transaction_seq: row.seq,
                event_tip: tip.to_string(),
            };
        }
        bindings_checked += 1;
    }
    BindingOutcome::Consistent { bindings_checked }
}

/// Everything `sysknife audit verify` checks, in one value.
///
/// Three independent questions, deliberately not collapsed into one enum:
/// is the authorisation record intact, is the approval record intact, and do
/// the two still agree. Collapsing them would let a clean transaction chain
/// mask a tampered approval trail in the summary line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerification {
    pub chain: VerifyOutcome,
    pub events: VerifyOutcome,
    pub binding: BindingOutcome,
    /// How many rows can name the account that acted, and why the rest cannot.
    ///
    /// Reported separately because `Intact` alone would be true and misleading: a
    /// host where every connection failed attribution produces a chain that
    /// verifies perfectly and answers "who acted" with nobody. The verdict is
    /// about tampering; this census is about how much the trail can tell you.
    ///
    /// `None` when the store could not be read at all, so no census was taken: a
    /// missing database, an unopenable one, an absent key. A readable but empty
    /// store is `Some`, with every count zero.
    ///
    /// Deliberately not a census of zero rows for the unreadable case: "nothing
    /// is known about attribution" and "the chain holds no rows" are different
    /// claims, and a zero that means the first reads as the second, which is the
    /// exact confusion this census exists to end.
    pub attribution: Option<AttributionCensus>,
}

/// What one row's principal column can attest, given the encoding that signed it.
///
/// Four outcomes, because the remedies differ and an audit report that collapses
/// them tells the operator to do the wrong thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowStanding {
    /// A `chain_version = 3` row whose signed principal names an account.
    NamesAccount,
    /// A `chain_version = 3` row signing `none:unattributed`: the daemon tried
    /// to attribute the connection and could not.
    AttributionFailed,
    /// Nothing the signature covers. A v1 or v2 row, whose encoding had no
    /// principal field, or a v3 row with a blank column, which also verifies as
    /// `Broken` once the walk reaches it.
    NotRecorded,
    /// Nothing here that a signature vouches for. Three sources: the column is
    /// populated on an encoding that does not sign it, or the value is one this
    /// binary cannot read back as something the daemon could have written, or the
    /// row declares an encoding this build does not know, in which case the
    /// principal may be absent or held somewhere this build cannot see.
    ///
    /// This build never writes any of those, so the first two are evidence of an
    /// out-of-band write and the third of a newer daemon. None of them is evidence
    /// of who acted.
    Unattested,
}

/// Which encoding, if any, signs the `caller_principal` column, and therefore
/// whether the column may be believed.
///
/// This is the load-bearing check in the census. [`ChainContent::canonical_bytes`]
/// pushes `caller_principal` into the signed bytes **only** in the v3 arm, so on a
/// v1 or v2 row that column is unsigned free space: anyone with write access to
/// the table can set it to `uid:0` and the chain still verifies `Intact`, because
/// there is no signature over it to break. Bucketing by the column instead of by
/// the encoding would let a plain `UPDATE` manufacture attribution, which is a
/// worse failure than the one this census was written to fix. Losing attribution
/// is a gap; inventing it is a lie.
fn standing(row: &ChainRow) -> RowStanding {
    // Empty treated as absent, and nothing trimmed, so this agrees with
    // `ChainRow::identity` exactly: it filters on `is_empty` and no more. An
    // earlier version trimmed first, which sent a whitespace-only v3 principal
    // into "written before the column existed" -- a row that in fact verifies
    // Intact and is an anomaly worth investigating. The schema stores `''` as
    // well as `NULL`, and `verify_chain` prints those two differently on purpose,
    // so both are reachable on real data.
    let stored = row.caller_principal.as_deref().filter(|p| !p.is_empty());
    match row.chain_version {
        CHAIN_VERSION_LEGACY | CHAIN_VERSION_V2 => match stored {
            None => RowStanding::NotRecorded,
            Some(_) => RowStanding::Unattested,
        },
        CHAIN_VERSION_V3 => match stored {
            None => RowStanding::NotRecorded,
            Some(p) => match crate::auth::CallerPrincipal::classify(p) {
                crate::auth::PrincipalClaim::Account => RowStanding::NamesAccount,
                crate::auth::PrincipalClaim::AttributionFailed => RowStanding::AttributionFailed,
                crate::auth::PrincipalClaim::Unrecognized => RowStanding::Unattested,
            },
        },
        // An encoding this binary does not know, which is any value outside 1..=3:
        // a newer daemon's, or a corrupt column. `verify_rows` already reports
        // `CannotVerify` for such a row, and the census must not claim an account
        // either, because this binary cannot say which fields that encoding signs
        // -- including whether it signs this column at all.
        _ => RowStanding::Unattested,
    }
}

/// Attribution census over every transaction row read.
///
/// Counted over all rows, not only the ones that verified, so a chain that
/// breaks at row 5 still reports what the remaining rows *claim* about who
/// acted. Those claims are only as good as the chain verdict beside them: unless
/// it is `Intact`, treat every count here as unproven, and note that
/// [`Self::rows`] can then exceed the verdict's `rows_checked`. A row past the
/// break may be perfectly authentic -- a deleted or reordered row breaks the link
/// while leaving every later signature valid -- so the surplus is the part of the
/// trail this command cannot vouch for, not proof of forgery. [`Self::rows`]
/// exists so a reader can see that gap instead of inferring it.
///
/// One counter is not enough, because a row can name no account for reasons with
/// different remedies. `none:unattributed` says the daemon tried and failed on a
/// host that could have attributed the call, which is a configuration problem to
/// chase in the daemon log. A v1 or v2 row says the encoding had no principal
/// field when the row was signed, which is history and cannot be repaired:
/// backfilling it would rewrite the bytes the signature covers. An unattested
/// value says something wrote to the column that should not have.
///
/// Splitting them keeps the report honest on an upgraded database. A single
/// "unattributed" count of `0` over a chain of pre-v3 rows reads as "every
/// action is attributed" when in fact none of them is.
///
/// Fields are private and [`Self::of`] is the only constructor that reads rows, so
/// a census cannot state totals that contradict the rows it describes.
/// `from_counts_for_tests` is the one other way to build one, and it is
/// not for production. That is not hypothetical tidiness: in 0.3.0 the MCP report
/// built its own all-zero attribution count on the `cannot_verify` path, where a
/// real count had already been computed, and the MCP tool and `audit verify
/// --json` then published different numbers for one database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributionCensus {
    named: u64,
    attribution_failed: u64,
    not_recorded: u64,
    unattested: u64,
    rows: u64,
}

impl AttributionCensus {
    /// Count the rows. The only way to obtain a census of real data.
    pub fn of(tx_rows: &[ChainRow]) -> Self {
        let mut census = Self {
            named: 0,
            attribution_failed: 0,
            not_recorded: 0,
            unattested: 0,
            rows: tx_rows.len() as u64,
        };
        for row in tx_rows {
            match standing(row) {
                RowStanding::NamesAccount => census.named += 1,
                RowStanding::AttributionFailed => census.attribution_failed += 1,
                RowStanding::NotRecorded => census.not_recorded += 1,
                RowStanding::Unattested => census.unattested += 1,
            }
        }
        census
    }

    /// Rows whose signed principal names an account (`uid:` or `token:`).
    ///
    /// Names an *account*, which is not a person: see `SECURITY.md` on shared
    /// logins, `su`, uid reuse, and on `token:vsock` proving possession of a
    /// file.
    pub fn named(&self) -> u64 {
        self.named
    }

    /// Rows signing `none:unattributed`, the daemon's admission that it could
    /// not name the caller.
    pub fn attribution_failed(&self) -> u64 {
        self.attribution_failed
    }

    /// Rows with no principal the signature covers, normally written before the
    /// column existed.
    pub fn not_recorded(&self) -> u64 {
        self.not_recorded
    }

    /// Rows carrying a principal no signature vouches for. Non-zero means
    /// investigate: nothing in SysKnife writes such a value.
    pub fn unattested(&self) -> u64 {
        self.unattested
    }

    /// Rows censused.
    ///
    /// The four row outcomes partition the rows, and [`Self::of`]
    /// increments exactly one bucket per row, so this equals their sum. State the
    /// partition rather than the arithmetic: a fifth bucket keeps the partition
    /// true, and any sum written out by hand somewhere else would not survive it.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// Rows that name no account, for any reason. What an operator asking "can
    /// this trail tell me who acted" has to subtract.
    ///
    /// Subtraction rather than addition on purpose: a fifth *non-naming* bucket
    /// cannot make this number stale, whereas summing the reasons would need
    /// editing here too. A future bucket that does name an account would have to
    /// be added to `named` instead, which is why `named` is the one counter this
    /// subtracts.
    pub fn unnamed(&self) -> u64 {
        self.rows - self.named
    }

    /// Build a census from counts, for rendering tests only.
    ///
    /// Behind the `test-support` feature rather than merely `#[doc(hidden)]`, which
    /// hides a function from documentation but not from callers. The CLI renderers
    /// live in another crate, where `cfg(test)` does not reach, and making them
    /// build signed `ChainRow` fixtures to assert on one line of prose would buy no
    /// safety; enabling the feature only as a dev-dependency keeps the door shut
    /// for production builds. [`Self::of`] is the constructor that reads rows.
    ///
    /// Panics if the counts overflow `u64`, rather than wrapping into a census
    /// whose `rows` is smaller than its buckets and whose [`Self::unnamed`] would
    /// then underflow.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_counts_for_tests(
        named: u64,
        attribution_failed: u64,
        not_recorded: u64,
        unattested: u64,
    ) -> Self {
        let rows = named
            .checked_add(attribution_failed)
            .and_then(|n| n.checked_add(not_recorded))
            .and_then(|n| n.checked_add(unattested))
            .expect("census counts must not overflow u64");
        Self {
            named,
            attribution_failed,
            not_recorded,
            unattested,
            rows,
        }
    }
}

impl AuditVerification {
    /// Worst result across all three checks.
    ///
    /// A detected tamper (`1`) outranks an inability to check (`2`): if the
    /// chain is provably broken, reporting "could not verify" because some
    /// *other* check was inconclusive would understate what is known.
    pub fn exit_code(&self) -> i32 {
        let codes = [
            outcome_to_exit_code(&self.chain),
            outcome_to_exit_code(&self.events),
            binding_outcome_to_exit_code(&self.binding),
        ];
        if codes.contains(&1) {
            1
        } else if codes.contains(&2) {
            2
        } else {
            0
        }
    }
}

/// Run all three checks with the daemon's key.
pub fn verify_all(
    key: &AuditKey,
    tx_rows: &[ChainRow],
    event_rows: &[EventRow],
) -> AuditVerification {
    AuditVerification {
        chain: verify_chain(key, tx_rows),
        events: verify_event_chain(key, event_rows),
        binding: verify_event_binding(tx_rows, event_rows),
        attribution: Some(AttributionCensus::of(tx_rows)),
    }
}

/// Run all three checks with only the exported public key (the auditor path).
pub fn verify_all_with_pubkey(
    verifying_key_hex: &str,
    tx_rows: &[ChainRow],
    event_rows: &[EventRow],
) -> AuditVerification {
    AuditVerification {
        chain: verify_chain_with_pubkey(verifying_key_hex, tx_rows),
        events: verify_event_chain_with_pubkey(verifying_key_hex, event_rows),
        binding: verify_event_binding(tx_rows, event_rows),
        attribution: Some(AttributionCensus::of(tx_rows)),
    }
}

/// Exit code for the binding check, on the same scale as
/// [`outcome_to_exit_code`]: a missing event is a detected tamper (`1`).
pub fn binding_outcome_to_exit_code(outcome: &BindingOutcome) -> i32 {
    match outcome {
        BindingOutcome::Consistent { .. } => 0,
        BindingOutcome::MissingEvent { .. } => 1,
    }
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
    let mut buf = CHECKPOINT_DOMAIN.to_vec();
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
    // `rows` is seq-sorted (ORDER BY seq ASC in the store; chain build order in
    // tests), so the tip seq is the last element and we can binary-search below.
    let current_max_seq = rows.last().map(|r| r.seq).unwrap_or(0);
    let mut checked = 0u64;
    for cp in checkpoints {
        let msg = checkpoint_message(cp.seq, &cp.chain_tip, &cp.created_at);
        if !signature_ok(&vk, &msg, &cp.signature) {
            return CheckpointOutcome::BadSignature { seq: cp.seq };
        }
        match rows.binary_search_by_key(&cp.seq, |r| r.seq) {
            Ok(idx) if rows[idx].chain_hash == cp.chain_tip => {}
            Ok(idx) => {
                return CheckpointOutcome::TipMismatch {
                    seq: cp.seq,
                    anchored: cp.chain_tip.clone(),
                    actual: rows[idx].chain_hash.clone(),
                };
            }
            Err(_) => {
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
            identity: ChainIdentity::V2 {
                caller_role: "Dev",
                event_tip: "",
            },
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

    /// Materialise the stored row that `content` would produce, so a test
    /// never hand-copies field-by-field and accidentally signs one thing while
    /// storing another.
    fn row_for(content: &ChainContent<'_>, prev: &str, chain_hash: String) -> ChainRow {
        let (chain_version, caller_role, event_tip, caller_principal) = match content.identity {
            ChainIdentity::LegacyV1 => (CHAIN_VERSION_LEGACY, None, None, None),
            ChainIdentity::V2 {
                caller_role,
                event_tip,
            } => (
                CHAIN_VERSION_V2,
                Some(caller_role.to_string()),
                Some(event_tip.to_string()),
                None,
            ),
            ChainIdentity::V3 {
                caller_role,
                event_tip,
                caller_principal,
            } => (
                CHAIN_VERSION_V3,
                Some(caller_role.to_string()),
                Some(event_tip.to_string()),
                Some(caller_principal.to_string()),
            ),
        };
        ChainRow {
            seq: content.seq,
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
            prev_chain_hash: prev.to_string(),
            chain_hash,
            chain_version,
            caller_role,
            event_tip,
            caller_principal,
        }
    }

    fn build_chain(key: &AuditKey, count: usize) -> Vec<ChainRow> {
        let mut rows = Vec::with_capacity(count);
        let mut prev = String::new();
        for i in 0..count {
            let seq = (i + 1) as u64;
            let txid = format!("tx{i}");
            let content = sample_content(seq, &txid);
            let hash = key.chain_hash(&content, &prev);
            rows.push(row_for(&content, &prev, hash.clone()));
            prev = hash;
        }
        rows
    }

    // ── caller identity in the signed content ─────────────────────────────

    #[test]
    fn caller_role_is_covered_by_the_row_signature() {
        // The whole point of the v2 encoding: two rows identical except for
        // who asked must not share a signature, or the chain cannot answer
        // "which role requested this".
        let key = fixed_key();
        let mut dev = sample_content(1, "txa");
        dev.identity = ChainIdentity::V2 {
            caller_role: "Dev",
            event_tip: "",
        };
        let mut boot = sample_content(1, "txa");
        boot.identity = ChainIdentity::V2 {
            caller_role: "Boot",
            event_tip: "",
        };
        assert_ne!(key.chain_hash(&dev, ""), key.chain_hash(&boot, ""));
    }

    #[test]
    fn event_tip_is_covered_by_the_row_signature() {
        let key = fixed_key();
        let mut empty = sample_content(1, "txa");
        empty.identity = ChainIdentity::V2 {
            caller_role: "Dev",
            event_tip: "",
        };
        let mut bound = sample_content(1, "txa");
        bound.identity = ChainIdentity::V2 {
            caller_role: "Dev",
            event_tip: "abc123",
        };
        assert_ne!(key.chain_hash(&empty, ""), key.chain_hash(&bound, ""));
    }

    #[test]
    fn a_legacy_row_written_before_the_migration_still_verifies() {
        // The migration contract. A chain written by v0.2.12 or earlier has no
        // caller_role column; re-encoding those rows with an empty identity
        // would report every historical row as Broken, i.e. an upgrade would
        // look exactly like a compromise.
        let key = fixed_key();
        let mut content = sample_content(1, "tx-legacy");
        content.identity = ChainIdentity::LegacyV1;
        let hash = key.chain_hash(&content, "");
        let row = row_for(&content, "", hash);
        assert_eq!(row.chain_version, CHAIN_VERSION_LEGACY);
        assert_eq!(row.caller_role, None);
        assert_eq!(
            verify_chain(&key, &[row]),
            VerifyOutcome::Intact { rows_checked: 1 }
        );
    }

    // ── v3: the row names the account, not just the role ──────────────────

    /// The point of the encoding: two callers who share a role must produce
    /// distinguishable signed records. If the principal were unsigned, or merely
    /// stored, this would pass while proving nothing.
    #[test]
    fn two_admins_are_distinguishable_in_the_signed_record() {
        let key = fixed_key();
        let mut alice = sample_content(1, "tx-alice");
        alice.identity = ChainIdentity::V3 {
            caller_role: "admin",
            event_tip: "",
            caller_principal: "uid:1000",
        };
        let mut bob = sample_content(1, "tx-alice");
        bob.identity = ChainIdentity::V3 {
            caller_role: "admin",
            event_tip: "",
            caller_principal: "uid:1001",
        };

        assert_ne!(
            key.chain_hash(&alice, ""),
            key.chain_hash(&bob, ""),
            "identical rows differing only in principal must sign differently, \
             otherwise the chain still cannot answer which account acted"
        );
    }

    /// Rewriting the stored principal must break verification. A field that can
    /// be edited after the fact records nothing an auditor can rely on.
    #[test]
    fn editing_the_stored_principal_breaks_the_row() {
        let key = fixed_key();
        let mut content = sample_content(1, "tx1");
        content.identity = ChainIdentity::V3 {
            caller_role: "admin",
            event_tip: "",
            caller_principal: "uid:1000",
        };
        let hash = key.chain_hash(&content, "");
        let mut row = row_for(&content, "", hash);
        row.caller_principal = Some("uid:0".to_string());

        assert!(
            matches!(verify_chain(&key, &[row]), VerifyOutcome::Broken { .. }),
            "a principal swapped to root must not verify"
        );
    }

    /// Downgrade is the other direction of the same attack: strip the principal
    /// and claim the row was written under v2, hiding which account acted. The
    /// v3 message signed a different byte string, so it cannot verify as v2.
    #[test]
    fn downgrading_a_v3_row_to_v2_to_hide_the_account_breaks_it() {
        let key = fixed_key();
        let mut content = sample_content(1, "tx1");
        content.identity = ChainIdentity::V3 {
            caller_role: "admin",
            event_tip: "",
            caller_principal: "uid:1000",
        };
        let hash = key.chain_hash(&content, "");
        let mut row = row_for(&content, "", hash);
        row.chain_version = CHAIN_VERSION_V2;
        row.caller_principal = None;

        assert!(
            matches!(verify_chain(&key, &[row]), VerifyOutcome::Broken { .. }),
            "a v3 row relabelled as v2 must not verify"
        );
    }

    /// A v3 row with no principal is self-contradictory, and so is one whose
    /// principal is blank: both claim an encoding that names an account while
    /// naming none. Treated as a break, not as "cannot verify", because the row
    /// contradicts itself rather than being written by a newer binary.
    #[test]
    fn a_v3_row_without_a_usable_principal_is_broken() {
        let key = fixed_key();
        let mut content = sample_content(1, "tx1");
        content.identity = ChainIdentity::V3 {
            caller_role: "admin",
            event_tip: "",
            caller_principal: "uid:1000",
        };
        let hash = key.chain_hash(&content, "");

        for absent in [None, Some(String::new())] {
            let mut row = row_for(&content, "", hash.clone());
            row.caller_principal = absent.clone();
            assert!(
                matches!(verify_chain(&key, &[row]), VerifyOutcome::Broken { .. }),
                "a v3 row with principal {absent:?} must be reported as broken"
            );
        }
    }

    /// A row *signed with* a blank principal must be rejected, and this is the
    /// only test that can prove the guard exists.
    ///
    /// The sibling test that blanks a stored principal proves something weaker:
    /// that row was signed with `uid:1000`, so it fails on signature mismatch
    /// whether or not `identity()` filters empties. Here the signature is
    /// perfectly valid for the blank principal, so the row verifies unless the
    /// filter refuses it. Without the guard a daemon could sign rows that name
    /// nobody and every one of them would report as intact.
    #[test]
    fn a_row_signed_with_a_blank_principal_is_rejected_even_though_it_signs() {
        let key = fixed_key();
        let mut content = sample_content(1, "tx-blank");
        content.identity = ChainIdentity::V3 {
            caller_role: "admin",
            event_tip: "",
            caller_principal: "",
        };
        let hash = key.chain_hash(&content, "");
        // Derived from the very content that was signed, so every other field
        // matches by construction. Building it by hand is how the first version
        // of this test came to pass for the wrong reason: a mismatched seq made
        // the row fail on signature, guard or no guard.
        let row = row_for(&content, "", hash);
        assert_eq!(
            row.caller_principal.as_deref(),
            Some(""),
            "fixture must store the blank principal it signed"
        );
        assert_eq!(row.chain_version, CHAIN_VERSION_V3);
        assert!(
            matches!(verify_chain(&key, &[row]), VerifyOutcome::Broken { .. }),
            "a v3 row naming nobody must be broken, not accepted"
        );
    }

    /// An attribution failure is a legitimate, verifiable identity: the daemon
    /// admits it could not name the caller, signs that admission, and the chain
    /// stays intact. If this ever reports Broken, every honest row on a host
    /// where `SO_PEERCRED` fails becomes a false tamper report.
    #[test]
    fn a_row_recording_an_attribution_failure_verifies() {
        let key = fixed_key();
        let principal = crate::auth::CallerPrincipal::Unattributed.as_signed_str();
        let mut content = sample_content(1, "tx-unattributed");
        content.identity = ChainIdentity::V3 {
            caller_role: "observer",
            event_tip: "",
            caller_principal: &principal,
        };
        let hash = key.chain_hash(&content, "");
        let row = row_for(&content, "", hash);

        assert_eq!(
            verify_chain(&key, &[row]),
            VerifyOutcome::Intact { rows_checked: 1 }
        );
    }

    /// The realistic database after two upgrades: legacy rows, v2 rows, then v3
    /// rows, all in one chain. Every generation has to keep verifying, which is
    /// the whole reason the encoding is selected per row.
    #[test]
    fn a_chain_spanning_all_three_encodings_verifies() {
        let key = fixed_key();
        let mut rows = Vec::new();
        let mut prev = String::new();
        for (i, identity) in [
            ChainIdentity::LegacyV1,
            ChainIdentity::V2 {
                caller_role: "dev",
                event_tip: "",
            },
            ChainIdentity::V3 {
                caller_role: "admin",
                event_tip: "",
                caller_principal: "uid:1000",
            },
            ChainIdentity::V3 {
                caller_role: "admin",
                event_tip: "",
                caller_principal: "token:vsock",
            },
        ]
        .into_iter()
        .enumerate()
        {
            let txid = format!("tx{i}");
            let mut content = sample_content((i + 1) as u64, &txid);
            content.identity = identity;
            let hash = key.chain_hash(&content, &prev);
            rows.push(row_for(&content, &prev, hash.clone()));
            prev = hash;
        }

        assert_eq!(
            verify_chain(&key, &rows),
            VerifyOutcome::Intact { rows_checked: 4 }
        );
    }

    /// Build a chain from a list of identities, signing each row properly, so no
    /// test signs one thing and stores another.
    fn chain_of(key: &AuditKey, identities: Vec<ChainIdentity<'_>>) -> Vec<ChainRow> {
        let mut rows = Vec::new();
        let mut prev = String::new();
        for (i, identity) in identities.into_iter().enumerate() {
            let txid = format!("tx{i}");
            let mut content = sample_content((i + 1) as u64, &txid);
            content.identity = identity;
            let hash = key.chain_hash(&content, &prev);
            rows.push(row_for(&content, &prev, hash.clone()));
            prev = hash;
        }
        rows
    }

    /// The census has to distinguish *why* a row names no account, because the
    /// reasons have different remedies: a `none:unattributed` row means
    /// `SO_PEERCRED` failed on a host that could have attributed it, while a v1
    /// or v2 row means the encoding had no principal field at the time it was
    /// signed. Reporting only the first understates an upgraded database.
    ///
    /// Every bucket gets a distinct count, so no permutation of the four can
    /// satisfy this assertion. The first version used 2/1/2 and still passed with
    /// the `named` and `not_recorded` arms swapped.
    #[test]
    fn the_census_separates_attribution_failures_from_encodings_without_the_field() {
        let key = fixed_key();
        let unattributed = crate::auth::CallerPrincipal::Unattributed.as_signed_str();
        let rows = chain_of(
            &key,
            vec![
                ChainIdentity::LegacyV1,
                ChainIdentity::V2 {
                    caller_role: "dev",
                    event_tip: "",
                },
                ChainIdentity::V3 {
                    caller_role: "admin",
                    event_tip: "",
                    caller_principal: "uid:1000",
                },
                ChainIdentity::V3 {
                    caller_role: "admin",
                    event_tip: "",
                    caller_principal: "uid:1001",
                },
                ChainIdentity::V3 {
                    caller_role: "admin",
                    event_tip: "",
                    caller_principal: "token:vsock",
                },
                ChainIdentity::V3 {
                    caller_role: "observer",
                    event_tip: "",
                    caller_principal: &unattributed,
                },
            ],
        );

        let verification = verify_all(&key, &rows, &[]);
        assert_eq!(
            verification.chain,
            VerifyOutcome::Intact { rows_checked: 6 },
            "every encoding must keep verifying; the census is not a verdict"
        );
        let census = verification
            .attribution
            .expect("rows were read, so a census was taken");
        assert_eq!(census.named(), 3);
        assert_eq!(census.attribution_failed(), 1);
        assert_eq!(census.not_recorded(), 2);
        assert_eq!(census.unattested(), 0);
        assert_eq!(census.rows(), 6);
        assert_eq!(
            census.unnamed(),
            3,
            "three of the six rows cannot name an account, by either reason"
        );
    }

    /// The forgery this census must not enable.
    ///
    /// `ChainContent::canonical_bytes` signs `caller_principal` only in the v3
    /// arm, so on a v1 or v2 row the column is unsigned free space. Anyone with write access
    /// to the table can set it, and no signature breaks. If the census bucketed
    /// by the column rather than by the encoding, a single `UPDATE` would turn
    /// "none of these rows names an account" into "every row names root", with an
    /// `Intact` verdict beside it. Losing attribution is a gap; inventing it is a
    /// lie, and this is the test that keeps the lie unavailable.
    #[test]
    fn a_principal_written_into_an_encoding_that_does_not_sign_it_is_never_an_account() {
        let key = fixed_key();
        let mut rows = chain_of(
            &key,
            vec![
                ChainIdentity::LegacyV1,
                ChainIdentity::V2 {
                    caller_role: "dev",
                    event_tip: "",
                },
            ],
        );
        // The out-of-band write. Not signed by either encoding, so the chain is
        // expected to stay Intact: the signature cannot see this.
        rows[0].caller_principal = Some("uid:0".to_string());
        rows[1].caller_principal = Some("uid:0".to_string());

        let verification = verify_all(&key, &rows, &[]);
        assert_eq!(
            verification.chain,
            VerifyOutcome::Intact { rows_checked: 2 },
            "no signature covers that column on v1/v2, so tampering with it is \
             invisible to verification -- which is exactly why the census must \
             not believe it"
        );
        let census = verification.attribution.expect("rows were read");
        assert_eq!(
            census.named(),
            0,
            "an unsigned column must never be credited as an account"
        );
        assert_eq!(
            census.unattested(),
            2,
            "and it must be reported as unattested, because nothing in SysKnife \
             writes that column on those encodings"
        );
        assert_eq!(census.unnamed(), 2);
    }

    /// A principal column that is present but empty must not be tallied as an
    /// account. The schema allows `''` as well as `NULL`, and `identity()`
    /// already reads the two the same way, so the census has to agree with it.
    #[test]
    fn a_blank_principal_column_is_counted_as_naming_nobody() {
        let key = fixed_key();
        let mut content = sample_content(1, "tx-blank-census");
        content.identity = ChainIdentity::V3 {
            caller_role: "admin",
            event_tip: "",
            caller_principal: "",
        };
        let hash = key.chain_hash(&content, "");
        let row = row_for(&content, "", hash);
        assert_eq!(row.caller_principal.as_deref(), Some(""));

        let verification = verify_all(&key, &[row], &[]);
        let census = verification.attribution.expect("a row was read");
        assert_eq!(census.named(), 0);
        assert_eq!(census.not_recorded(), 1);
        assert_eq!(census.rows(), 1);
        assert!(
            matches!(verification.chain, VerifyOutcome::Broken { .. }),
            "and the row is still reported as broken once the walk reaches it, \
             so census and verdict agree"
        );
    }

    /// Values that look like a principal but name nobody. None of these can be
    /// written by the daemon (`CallerPrincipal::as_signed_str` always renders
    /// `scheme:value` with a non-empty value), so each one is evidence of an
    /// out-of-band write. Counting them as accounts would be this commit's own
    /// defect one level down: `none:overflow` in particular is a plausible future
    /// spelling of a *failure*, and crediting it as an account would invert its
    /// meaning.
    #[test]
    fn a_principal_this_binary_cannot_read_is_counted_as_unattested_not_as_an_account() {
        let key = fixed_key();
        for forged in [
            "garbage",
            "uid:",
            "none:overflow",
            // Whitespace is signed content like any other, so this row verifies
            // Intact. It still names nobody, and it belongs in the bucket that
            // asks for an investigation rather than the one that explains
            // pre-0.3.0 history: nothing in SysKnife writes it.
            "  ",
            "UID:1000",
            // A known scheme with a value the daemon could not have rendered.
            "uid:notanumber",
            "uid:1000:extra",
            "token:not-vsock",
        ] {
            let mut content = sample_content(1, "tx-forged");
            content.identity = ChainIdentity::V3 {
                caller_role: "admin",
                event_tip: "",
                caller_principal: forged,
            };
            let hash = key.chain_hash(&content, "");
            let row = row_for(&content, "", hash);
            let census = verify_all(&key, &[row], &[])
                .attribution
                .expect("a row was read");
            assert_eq!(
                census.named(),
                0,
                "{forged:?} names no account and must not be counted as one"
            );
            assert_eq!(
                census.unnamed(),
                1,
                "{forged:?} must be counted among the rows naming nobody"
            );
            assert_eq!(
                census.unattested(),
                1,
                "{forged:?} is signed content the daemon never writes, so it is a \
                 finding to investigate, not history to explain away"
            );
            assert_eq!(
                census.not_recorded(),
                0,
                "{forged:?} is present, so it must not be reported as a row that \
                 predates the column"
            );
        }
    }

    /// The case that made the single counter misleading: a database written
    /// entirely before the principal column existed reports zero attribution
    /// failures, which reads as "everything is attributed". Every row in it names
    /// nobody, so `unnamed` must account for all of them.
    #[test]
    fn a_chain_predating_the_principal_field_reports_no_row_as_attributed() {
        let key = fixed_key();
        let rows = chain_of(
            &key,
            vec![
                ChainIdentity::LegacyV1,
                ChainIdentity::V2 {
                    caller_role: "dev",
                    event_tip: "",
                },
            ],
        );

        let verification = verify_all(&key, &rows, &[]);
        assert_eq!(
            verification.chain,
            VerifyOutcome::Intact { rows_checked: 2 },
            "legacy rows must keep verifying; the census is not a verdict"
        );
        let census = verification.attribution.expect("rows were read");
        assert_eq!(census.attribution_failed(), 0);
        assert_eq!(census.named(), 0);
        assert_eq!(census.not_recorded(), 2);
        assert_eq!(census.unnamed(), 2);
    }

    /// The census spans every row read, while verification stops at the first
    /// break. That is deliberate, and it is also the reason the counts are claims
    /// rather than findings: on a broken chain the rows after the break were
    /// written by whoever broke it. `rows()` is what lets a reader see the gap
    /// between what was counted and what was checked.
    #[test]
    fn a_broken_chain_censuses_more_rows_than_it_verified() {
        let key = fixed_key();
        let mut rows = chain_of(
            &key,
            vec![
                ChainIdentity::V3 {
                    caller_role: "admin",
                    event_tip: "",
                    caller_principal: "uid:1000",
                },
                ChainIdentity::V3 {
                    caller_role: "admin",
                    event_tip: "",
                    caller_principal: "uid:1000",
                },
                ChainIdentity::V3 {
                    caller_role: "admin",
                    event_tip: "",
                    caller_principal: "uid:1000",
                },
            ],
        );
        rows[1].summary = "tampered".to_string();

        let verification = verify_all(&key, &rows, &[]);
        let rows_checked = match verification.chain {
            VerifyOutcome::Broken { rows_checked, .. } => rows_checked,
            ref other => panic!("expected a detected tamper, got {other:?}"),
        };
        let census = verification.attribution.expect("rows were read");
        assert_eq!(rows_checked, 1, "the walk stops at the first broken row");
        assert_eq!(
            census.rows(),
            3,
            "while the census still describes every row read"
        );
        assert!(
            census.rows() > rows_checked,
            "the report must be able to show that more was counted than checked"
        );
    }

    /// The auditor path takes the same census as the keyholder path. It is the
    /// one an external reviewer runs, so a census wired only into `verify_all`
    /// would leave exactly that audience with nothing.
    #[test]
    fn the_pubkey_only_path_takes_the_same_census() {
        let key = fixed_key();
        let unattributed = crate::auth::CallerPrincipal::Unattributed.as_signed_str();
        let rows = chain_of(
            &key,
            vec![
                ChainIdentity::V3 {
                    caller_role: "admin",
                    event_tip: "",
                    caller_principal: "uid:1000",
                },
                ChainIdentity::V3 {
                    caller_role: "observer",
                    event_tip: "",
                    caller_principal: &unattributed,
                },
            ],
        );

        let with_key = verify_all(&key, &rows, &[]).attribution;
        let with_pubkey = verify_all_with_pubkey(&key.verifying_key_hex(), &rows, &[]).attribution;
        assert_eq!(
            with_key, with_pubkey,
            "the auditor must see the same attribution numbers as the keyholder"
        );
        let census = with_pubkey.expect("rows were read");
        assert_eq!(census.named(), 1);
        assert_eq!(census.attribution_failed(), 1);
    }

    /// Attribution must not move the exit code. `Intact` is a statement about
    /// tampering, and `SECURITY.md` leans on that separation: a host where every
    /// connection failed attribution still has an untampered chain, and turning
    /// that into a non-zero exit would train operators to ignore the real signal.
    #[test]
    fn a_chain_that_names_nobody_still_exits_zero() {
        let key = fixed_key();
        let unattributed = crate::auth::CallerPrincipal::Unattributed.as_signed_str();
        let rows = chain_of(
            &key,
            vec![
                ChainIdentity::LegacyV1,
                ChainIdentity::V3 {
                    caller_role: "observer",
                    event_tip: "",
                    caller_principal: &unattributed,
                },
            ],
        );

        let verification = verify_all(&key, &rows, &[]);
        let census = verification.attribution.expect("rows were read");
        assert_eq!(census.unnamed(), 2, "not one row names an account");
        assert_eq!(
            verification.exit_code(),
            0,
            "yet nothing was tampered with, so the command must succeed"
        );
    }

    /// A row from a future encoding is "cannot verify", never "broken": an older
    /// binary reading a newer chain has found no tampering, only work it cannot
    /// reproduce. The message must say the supported range so the operator knows
    /// the fix is a newer build.
    #[test]
    fn a_future_encoding_reports_cannot_verify_with_the_supported_range() {
        let key = fixed_key();
        let content = sample_content(1, "tx1");
        let hash = key.chain_hash(&content, "");
        let mut row = row_for(&content, "", hash);
        row.chain_version = CHAIN_VERSION_CURRENT + 1;

        match verify_chain(&key, &[row]) {
            VerifyOutcome::CannotVerify { reason } => {
                assert!(
                    reason.contains(&format!("chain_version={}", CHAIN_VERSION_CURRENT + 1)),
                    "name the version found, got: {reason}"
                );
                assert!(
                    reason.contains(&CHAIN_VERSION_CURRENT.to_string()),
                    "and the newest version understood, got: {reason}"
                );
            }
            other => panic!("a future encoding must not be reported as tampering: {other:?}"),
        }
    }

    /// A row encoded exactly as the v0.2.16 binary would have encoded it: the
    /// content is synthetic, the hash is what that release's v2 encoder produced
    /// over it. No in-memory test can prove this property, because every other
    /// test in this module signs and verifies inside one process, so both halves
    /// move together whenever a constant changes.
    ///
    /// Concretely, this catches the aliasing hazard the `ChainIdentity` docs warn
    /// about: `identity()` dispatches stored `chain_version` values against
    /// `CHAIN_VERSION_CURRENT`, and the v2 encoder used to *sign* that same
    /// constant. Bump it for a new encoding and both the dispatch and the message
    /// shift, so every v2 row on disk stops verifying while the whole unit suite
    /// stays green. Only a golden vector notices.
    #[test]
    fn a_row_written_by_the_previous_release_still_verifies() {
        const GOLDEN_V2_CHAIN_HASH: &str = "ba12cbe49a149387898bc30f1e8d409effa025ab8e440e6e72bedf060afc831e45d9be264d6b18b7e0ef2f2b3584dbc6953b535546cecbbdc3d7ac666cae4d0a";

        let key = fixed_key();
        let row = ChainRow {
            seq: 7,
            key_id: CURRENT_KEY_ID.to_string(),
            transaction_id: "tx-golden".to_string(),
            request_id: "req-golden".to_string(),
            request_hash: "hash-golden".to_string(),
            action_name: "AptInstall".to_string(),
            risk_level: RiskLevel::Medium,
            summary: "install ripgrep".to_string(),
            approval_id: Some("appr-golden".to_string()),
            warnings_json: "[]".to_string(),
            created_at: "2026-07-29T00:00:00Z".to_string(),
            prev_chain_hash: String::new(),
            chain_hash: GOLDEN_V2_CHAIN_HASH.to_string(),
            chain_version: 2,
            caller_role: Some("admin".to_string()),
            event_tip: Some("eventtip-golden".to_string()),
            caller_principal: None,
        };

        assert_eq!(
            verify_chain(&key, std::slice::from_ref(&row)),
            VerifyOutcome::Intact { rows_checked: 1 },
            "a v2 row on disk must verify under this binary; if this fails, the v2 \
             encoding or its version dispatch changed and existing audit logs are unreadable"
        );

        // Without this half the frozen constant is decorative: a build that
        // skipped signature checking entirely would still pass the assertion
        // above. Flipping one nibble must be rejected.
        let mut tampered = row;
        let flipped = match GOLDEN_V2_CHAIN_HASH.strip_prefix('b') {
            Some(rest) => format!("a{rest}"),
            None => format!("b{}", &GOLDEN_V2_CHAIN_HASH[1..]),
        };
        tampered.chain_hash = flipped;
        assert!(
            matches!(
                verify_chain(&key, &[tampered]),
                VerifyOutcome::Broken { .. }
            ),
            "a golden row with one nibble changed must not verify"
        );
    }

    /// The v1 encoding is still claimed verifiable, and until now was protected
    /// only by tests that sign and verify in one process. Frozen here for the
    /// same reason as v2.
    #[test]
    fn a_legacy_v1_row_on_disk_still_verifies() {
        const GOLDEN_V1_CHAIN_HASH: &str = "ce8b47c15414e989e099303b826fcd9985360b794220cefbbf9689d25f31fe173283687feb6d1dd265ae5aca94c8bcfb87ce33ba8c954fafdad18a59cd97c702";

        let row = ChainRow {
            chain_version: 1,
            caller_role: None,
            event_tip: None,
            caller_principal: None,
            chain_hash: GOLDEN_V1_CHAIN_HASH.to_string(),
            ..golden_row_shape()
        };
        assert_eq!(
            verify_chain(&fixed_key(), &[row]),
            VerifyOutcome::Intact { rows_checked: 1 }
        );
    }

    /// And v3, frozen now while the encoder that produces it is the one under
    /// review. When v4 arrives, v3 rows will be in exactly the position v2 rows
    /// were in before this change, and this is the test that will notice.
    #[test]
    fn a_v3_row_on_disk_still_verifies() {
        const GOLDEN_V3_CHAIN_HASH: &str = "3c0d05f6ccaf9e65ccb796d4ffe96eb31a2ea67e446217c5234af916dc959d0f2c0ee3d3e5b525aece791ee7d6507efb98dcdd79f0d74dde4273859aa9627d08";

        let row = ChainRow {
            chain_version: 3,
            caller_role: Some("admin".to_string()),
            event_tip: Some("eventtip-golden".to_string()),
            caller_principal: Some("uid:1000".to_string()),
            chain_hash: GOLDEN_V3_CHAIN_HASH.to_string(),
            ..golden_row_shape()
        };
        assert_eq!(
            verify_chain(&fixed_key(), &[row]),
            VerifyOutcome::Intact { rows_checked: 1 }
        );
    }

    /// The golden rows above all have an empty `prev_chain_hash`, an approval id,
    /// and content with no bytes the escape table touches. This one has the
    /// opposite of each: a non-empty predecessor, no approval id, and a summary
    /// carrying a backslash, `0x1F`, `0x1E`, and a NUL. A refactor of the escape
    /// table or of the `approval_id: None` mapping changes this hash and nothing
    /// else in the suite.
    #[test]
    fn the_escape_table_and_absent_approval_encoding_are_frozen() {
        const GOLDEN_V2_AWKWARD_CHAIN_HASH: &str = "e6face6fe2346fc0f6c5c1e5845255579c8f08738406b88b0a1f6dbdf8ff85090a4b80d95bd0927ef54b0a2c4810d52ebb4bbf76cb68c865a7748df26442aa05";

        let key = fixed_key();
        let content = ChainContent {
            seq: 8,
            approval_id: None,
            summary: "back\\slash and \x1funit and \x1erecord and nul\0byte",
            identity: ChainIdentity::V2 {
                caller_role: "dev",
                event_tip: "",
            },
            ..golden_content_shape()
        };
        assert_eq!(
            key.chain_hash(&content, "ba12cbe4"),
            GOLDEN_V2_AWKWARD_CHAIN_HASH,
            "the canonical encoding of escapes, an absent approval id, or a \
             non-empty prev_chain_hash changed"
        );
    }

    /// Shared literal content for the golden vectors. Spelled out rather than
    /// derived from `sample_content` so a future edit to that helper cannot move
    /// what the frozen hashes describe.
    fn golden_content_shape() -> ChainContent<'static> {
        ChainContent {
            seq: 7,
            key_id: CURRENT_KEY_ID,
            transaction_id: "tx-golden",
            request_id: "req-golden",
            request_hash: "hash-golden",
            action_name: "AptInstall",
            risk_level: RiskLevel::Medium,
            summary: "install ripgrep",
            approval_id: Some("appr-golden"),
            warnings_json: "[]",
            created_at: "2026-07-29T00:00:00Z",
            identity: ChainIdentity::LegacyV1,
        }
    }

    /// The stored-row twin of `golden_content_shape`.
    fn golden_row_shape() -> ChainRow {
        ChainRow {
            seq: 7,
            key_id: CURRENT_KEY_ID.to_string(),
            transaction_id: "tx-golden".to_string(),
            request_id: "req-golden".to_string(),
            request_hash: "hash-golden".to_string(),
            action_name: "AptInstall".to_string(),
            risk_level: RiskLevel::Medium,
            summary: "install ripgrep".to_string(),
            approval_id: Some("appr-golden".to_string()),
            warnings_json: "[]".to_string(),
            created_at: "2026-07-29T00:00:00Z".to_string(),
            prev_chain_hash: String::new(),
            chain_hash: String::new(),
            chain_version: 1,
            caller_role: None,
            event_tip: None,
            caller_principal: None,
        }
    }

    #[test]
    fn a_chain_that_spans_the_migration_verifies_end_to_end() {
        // The realistic upgrade shape: old rows, then new rows appended by the
        // upgraded daemon, in one chain.
        let key = fixed_key();
        let mut rows = Vec::new();
        let mut prev = String::new();
        for (i, identity) in [
            ChainIdentity::LegacyV1,
            ChainIdentity::LegacyV1,
            ChainIdentity::V2 {
                caller_role: "Dev",
                event_tip: "",
            },
            ChainIdentity::V2 {
                caller_role: "Boot",
                event_tip: "",
            },
        ]
        .into_iter()
        .enumerate()
        {
            let txid = format!("tx{i}");
            let mut content = sample_content((i + 1) as u64, &txid);
            content.identity = identity;
            let hash = key.chain_hash(&content, &prev);
            rows.push(row_for(&content, &prev, hash.clone()));
            prev = hash;
        }
        assert_eq!(
            verify_chain(&key, &rows),
            VerifyOutcome::Intact { rows_checked: 4 }
        );
    }

    #[test]
    fn downgrading_a_v2_row_to_hide_the_caller_role_breaks_it() {
        // The attack the version column might invite: relabel a v2 row as
        // legacy and drop the identity columns, so verification re-encodes it
        // without caller_role. The stored signature was made over the v2
        // message, so it cannot verify against the shorter one.
        let key = fixed_key();
        let mut rows = build_chain(&key, 2);
        rows[1].chain_version = CHAIN_VERSION_LEGACY;
        rows[1].caller_role = None;
        rows[1].event_tip = None;
        match verify_chain(&key, &rows) {
            VerifyOutcome::Broken {
                first_broken_seq, ..
            } => assert_eq!(first_broken_seq, 2),
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[test]
    fn a_v2_row_with_a_nulled_caller_role_is_broken_not_merely_unverifiable() {
        // Nulling the column while leaving chain_version=2 is a
        // self-contradictory row, not an infrastructure problem. It must map
        // to exit code 1 (tamper detected), never 2 (could not check) — a CI
        // gate that treats 2 as "skip" would otherwise wave it through.
        let key = fixed_key();
        let mut rows = build_chain(&key, 1);
        rows[0].caller_role = None;
        let outcome = verify_chain(&key, &rows);
        assert!(matches!(outcome, VerifyOutcome::Broken { .. }));
        assert_eq!(outcome_to_exit_code(&outcome), 1);
    }

    #[test]
    fn a_chain_version_this_binary_does_not_know_is_cannot_verify() {
        // An older binary reading a newer chain genuinely cannot reproduce the
        // message. That is exit 2, distinct from a detected break.
        let key = fixed_key();
        let mut rows = build_chain(&key, 1);
        rows[0].chain_version = CHAIN_VERSION_CURRENT + 1;
        let outcome = verify_chain(&key, &rows);
        assert!(matches!(outcome, VerifyOutcome::CannotVerify { .. }));
        assert_eq!(outcome_to_exit_code(&outcome), 2);
    }

    // ── approval-event chain ──────────────────────────────────────────────

    fn event_content<'a>(seq: u64, kind: AuditEventKind, txid: &'a str) -> EventContent<'a> {
        EventContent {
            seq,
            key_id: CURRENT_KEY_ID,
            kind,
            transaction_id: txid,
            receipt_digest: "digest-abc",
            created_at: "2026-04-24T12:00:00Z",
        }
    }

    fn build_event_chain(key: &AuditKey, kinds: &[AuditEventKind]) -> Vec<EventRow> {
        let mut rows = Vec::with_capacity(kinds.len());
        let mut prev = String::new();
        for (i, kind) in kinds.iter().enumerate() {
            let seq = (i + 1) as u64;
            let txid = format!("tx{i}");
            let content = event_content(seq, *kind, &txid);
            let hash = key.event_hash(&content, &prev);
            rows.push(EventRow {
                seq,
                key_id: content.key_id.to_string(),
                kind: content.kind.as_str().to_string(),
                transaction_id: content.transaction_id.to_string(),
                receipt_digest: content.receipt_digest.to_string(),
                created_at: content.created_at.to_string(),
                prev_chain_hash: prev.clone(),
                chain_hash: hash.clone(),
            });
            prev = hash;
        }
        rows
    }

    #[test]
    fn event_kind_spellings_are_stable() {
        // These strings are inside the signed message. Renaming one silently
        // invalidates every event already written.
        assert_eq!(AuditEventKind::ApprovalGranted.as_str(), "approval_granted");
        assert_eq!(
            AuditEventKind::ApprovalConsumed.as_str(),
            "approval_consumed"
        );
        assert_eq!(AuditEventKind::ApprovalRevoked.as_str(), "approval_revoked");
    }

    #[test]
    fn intact_event_chain_verifies() {
        let key = fixed_key();
        let rows = build_event_chain(
            &key,
            &[
                AuditEventKind::ApprovalGranted,
                AuditEventKind::ApprovalConsumed,
            ],
        );
        assert_eq!(
            verify_event_chain(&key, &rows),
            VerifyOutcome::Intact { rows_checked: 2 }
        );
    }

    #[test]
    fn deleting_an_approval_event_from_the_middle_breaks_the_event_chain() {
        // The finding this chain exists for: before it, deleting the record
        // that an approval happened left `audit verify` reporting Intact.
        let key = fixed_key();
        let mut rows = build_event_chain(
            &key,
            &[
                AuditEventKind::ApprovalGranted,
                AuditEventKind::ApprovalConsumed,
                AuditEventKind::ApprovalRevoked,
            ],
        );
        rows.remove(1);
        match verify_event_chain(&key, &rows) {
            VerifyOutcome::Broken {
                first_broken_seq, ..
            } => assert_eq!(first_broken_seq, 3),
            other => panic!("expected Broken, got {other:?}"),
        }
    }

    #[test]
    fn relabelling_a_revocation_as_a_grant_breaks_the_event_chain() {
        let key = fixed_key();
        let mut rows = build_event_chain(&key, &[AuditEventKind::ApprovalRevoked]);
        rows[0].kind = AuditEventKind::ApprovalGranted.as_str().to_string();
        assert!(matches!(
            verify_event_chain(&key, &rows),
            VerifyOutcome::Broken { .. }
        ));
    }

    #[test]
    fn an_unrecognised_event_kind_is_a_break_not_a_panic() {
        let key = fixed_key();
        let mut rows = build_event_chain(&key, &[AuditEventKind::ApprovalGranted]);
        rows[0].kind = "approval_unicorned".to_string();
        assert!(matches!(
            verify_event_chain(&key, &rows),
            VerifyOutcome::Broken { .. }
        ));
    }

    #[test]
    fn a_row_signature_cannot_be_replayed_as_an_event_signature() {
        // Domain separation, checked functionally rather than by comparing the
        // tag constants: the tags test proves the bytes differ, this proves the
        // difference actually reaches the verifier.
        let key = fixed_key();
        let content = event_content(1, AuditEventKind::ApprovalGranted, "tx0");
        let event_sig = key.event_hash(&content, "");
        let row_sig = key.chain_hash(&sample_content(1, "tx0"), "");
        assert_ne!(event_sig, row_sig);

        let mut rows = build_event_chain(&key, &[AuditEventKind::ApprovalGranted]);
        rows[0].chain_hash = row_sig;
        assert!(matches!(
            verify_event_chain(&key, &rows),
            VerifyOutcome::Broken { .. }
        ));
    }

    // ── cross-chain binding ───────────────────────────────────────────────

    #[test]
    fn deleting_the_last_approval_event_is_caught_by_the_transaction_binding() {
        // Truncating the *tail* of the event chain leaves a self-consistent
        // event chain — the walk alone cannot see it. It is caught because a
        // later transaction row signed the tip that no longer exists, and the
        // transaction chain is what checkpoints anchor.
        let key = fixed_key();
        let events = build_event_chain(
            &key,
            &[
                AuditEventKind::ApprovalGranted,
                AuditEventKind::ApprovalConsumed,
            ],
        );
        let mut content = sample_content(1, "tx-after");
        content.identity = ChainIdentity::V2 {
            caller_role: "Dev",
            event_tip: &events[1].chain_hash,
        };
        let hash = key.chain_hash(&content, "");
        let tx_rows = vec![row_for(&content, "", hash)];

        assert_eq!(
            verify_event_binding(&tx_rows, &events),
            BindingOutcome::Consistent {
                bindings_checked: 1
            }
        );

        let truncated = &events[..1];
        assert_eq!(
            verify_event_chain(&key, truncated),
            VerifyOutcome::Intact { rows_checked: 1 },
            "a truncated event chain still walks clean; the binding is the detector"
        );
        match verify_event_binding(&tx_rows, truncated) {
            BindingOutcome::MissingEvent {
                transaction_seq, ..
            } => assert_eq!(transaction_seq, 1),
            other => panic!("expected MissingEvent, got {other:?}"),
        }
    }

    #[test]
    fn legacy_rows_carry_no_binding_to_check() {
        // Rows written before the migration never committed to an event tip.
        // They must not be counted as bindings, and must not fail the check.
        let key = fixed_key();
        let mut content = sample_content(1, "tx-legacy");
        content.identity = ChainIdentity::LegacyV1;
        let hash = key.chain_hash(&content, "");
        let rows = vec![row_for(&content, "", hash)];
        assert_eq!(
            verify_event_binding(&rows, &[]),
            BindingOutcome::Consistent {
                bindings_checked: 0
            }
        );
    }

    #[test]
    fn a_detected_break_outranks_an_inconclusive_check_in_the_exit_code() {
        // If one check proves tampering and another merely cannot run, the
        // command must report the tamper. Reporting 2 ("could not verify")
        // would let a CI gate that treats 2 as a skip wave a broken chain
        // through.
        let verification = AuditVerification {
            chain: VerifyOutcome::Broken {
                rows_checked: 1,
                first_broken_seq: 2,
                first_broken_transaction_id: "tx".to_string(),
                expected: "e".to_string(),
                actual: "a".to_string(),
            },
            events: VerifyOutcome::CannotVerify {
                reason: "no key".to_string(),
            },
            binding: BindingOutcome::Consistent {
                bindings_checked: 0,
            },
            attribution: None,
        };
        assert_eq!(verification.exit_code(), 1);
    }

    #[test]
    fn a_clean_transaction_chain_does_not_mask_a_broken_event_chain() {
        let verification = AuditVerification {
            chain: VerifyOutcome::Intact { rows_checked: 3 },
            events: VerifyOutcome::Intact { rows_checked: 1 },
            binding: BindingOutcome::MissingEvent {
                transaction_seq: 3,
                event_tip: "abc".to_string(),
            },
            attribution: None,
        };
        assert_eq!(verification.exit_code(), 1);
    }

    #[test]
    fn all_three_clean_is_exit_zero() {
        let verification = AuditVerification {
            chain: VerifyOutcome::Intact { rows_checked: 3 },
            events: VerifyOutcome::Intact { rows_checked: 2 },
            binding: BindingOutcome::Consistent {
                bindings_checked: 1,
            },
            attribution: None,
        };
        assert_eq!(verification.exit_code(), 0);
    }

    #[test]
    fn binding_exit_codes_split_clean_from_tampered() {
        assert_eq!(
            binding_outcome_to_exit_code(&BindingOutcome::Consistent {
                bindings_checked: 0
            }),
            0
        );
        assert_eq!(
            binding_outcome_to_exit_code(&BindingOutcome::MissingEvent {
                transaction_seq: 7,
                event_tip: "abc".to_string()
            }),
            1
        );
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
            // Carries a principal on purpose: without one the row is rejected as
            // self-contradictory *before* any signature is checked, and this test
            // exists to prove the walk stops on a bad signature.
            caller_principal: Some("uid:1000".to_string()),
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
            chain_version: CHAIN_VERSION_CURRENT,
            caller_role: Some("Dev".to_string()),
            event_tip: Some(String::new()),
        };

        // Renumber the genuine seq=2/3 rows so seq is still 1..=4.
        let mut rest: Vec<ChainRow> = rows.split_off(1);
        for r in rest.iter_mut() {
            r.seq += 1;
        }
        rows.push(forged);
        rows.extend(rest);

        // The fixture is deterministic: the forged row sits at seq=2 with a
        // signature that cannot verify, so the walk must stop exactly there.
        // Accepting "2 or 3" let an off-by-one in `verify_rows` pass.
        let outcome = verify_chain(&key, &rows);
        match outcome {
            VerifyOutcome::Broken {
                first_broken_seq, ..
            } => assert_eq!(
                first_broken_seq, 2,
                "the verifier must flag the forged row itself, not a later one"
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

    #[test]
    fn domain_tags_are_distinct_and_prefix_free() {
        // Security invariant: row and checkpoint signatures can never
        // cross-verify because their signed messages start with distinct,
        // prefix-free domain tags.
        // Checked pairwise over the whole set rather than as a hand-written
        // list: adding a fourth tag to a hand-written list silently leaves the
        // new tag unchecked against the old ones.
        let tags: [(&str, &[u8]); 4] = [
            ("row", ROW_DOMAIN),
            ("checkpoint", CHECKPOINT_DOMAIN),
            ("approval", APPROVAL_DOMAIN),
            ("event", EVENT_DOMAIN),
        ];
        for (i, (name_a, a)) in tags.iter().enumerate() {
            for (name_b, b) in tags.iter().skip(i + 1) {
                assert_ne!(a, b, "{name_a} and {name_b} share a domain tag");
                assert!(!a.starts_with(b), "{name_a} is prefixed by {name_b}");
                assert!(!b.starts_with(a), "{name_b} is prefixed by {name_a}");
            }
        }
    }

    #[test]
    fn approval_receipt_framing_is_injective() {
        // The signed receipt message must be injective in
        // (transaction_id, request_hash). Without `push_field` escaping, the
        // ambiguous pair below would collide because a raw 0x1F separator
        // cannot be distinguished from a 0x1F inside a field value.
        let key = fixed_key();
        let sep = "\u{1f}";
        let a = key.approval_receipt(&format!("tx{sep}b"), "c");
        let b = key.approval_receipt("tx", &format!("b{sep}c"));
        assert_ne!(a, b, "0x1F in a field must not alias distinct receipts");

        // Sanity: the derivation is deterministic (Ed25519, same inputs).
        assert_eq!(
            key.approval_receipt("tx-1", "hash-1"),
            key.approval_receipt("tx-1", "hash-1"),
        );
        // And the commitment is exactly SHA-256 of the receipt.
        assert_eq!(
            key.approval_commitment("tx-1", "hash-1"),
            approval_receipt_digest(&key.approval_receipt("tx-1", "hash-1")),
        );
    }
}
