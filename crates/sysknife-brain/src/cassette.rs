//! Deterministic record/replay for the LLM call, so a story suite can run
//! offline, for free, and give the same answer twice.
//!
//! One `record` run captures every distinct `LlmProvider::complete` call to a
//! JSON file; every later `replay` run answers from that file and never touches
//! the network. The wrapper sits at the [`LlmProvider`] boundary on purpose:
//! everything above it still runs for real — prompt assembly, the tool-use loop,
//! the safety fence, the ActionSpec risk substitution, the daemon IPC. Only the
//! network hop is replayed. Recording the *story verdicts* instead would stub out
//! the planner and leave assertions that pass without testing anything.
//!
//! Keyed by a sha256 of `(surface, system, messages, tools, max_tokens)` rather
//! than by call order, so a replay survives running the stories in a different
//! order. The surface is `provider/model`, and it is part of the hash: a cassette
//! recorded against one model must never answer on behalf of another, because it
//! is not evidence about that model.
//!
//! Only the key and the output are stored. The prompt is folded into the hash and
//! not written verbatim — the system prompt alone is ~39 KB, so storing it per
//! entry would dwarf the outputs. The cost is that a cassette is not a readable
//! transcript; `meta.system_prompt_sha256` is the mitigation, so a wall of misses
//! can say "the prompt changed" instead of leaving the reader guessing.
//!
//! ## Replay is strict, and says so out loud
//!
//! A miss returns an error, and every call also appends its outcome to a ledger
//! next to the cassette. Two reasons the ledger is not redundant:
//!
//! 1. A caller may swallow the error. Provider errors propagate today, but a
//!    future retry or provider-fallback path would turn a miss into a live call
//!    against a different model and nobody would notice.
//! 2. A run that replayed *nothing* looks exactly like a run where everything
//!    passed. The ledger lets the harness assert `hits > 0`, which is the
//!    difference between "50 stories agreed with the recording" and "the suite
//!    never asked".
//!
//! Appended per call rather than summarised at exit, so a process killed
//! mid-suite still leaves its evidence behind.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::provider::{Completion, LlmProvider, Message, ProviderError, ToolDefinition};

/// On-disk format version. Bump when the entry shape changes.
///
/// A *newer* file is refused rather than guessed at, so a shape this binary does
/// not understand cannot be silently half-read. An *older* one is read: every
/// version so far has only added optional fields, and refusing v1 would have
/// thrown away three committed recordings to gain nothing.
///
/// - v1 — entries carry `output` only.
/// - v2 — an entry may instead carry `rejection`, so a call the provider refused
///   is reproducible. See `RecordedRejection` in this module.
pub const CASSETTE_VERSION: u32 = 2;

/// Environment variable naming the cassette file.
pub const ENV_CASSETTE: &str = "SYSKNIFE_CASSETTE";
/// Environment variable selecting `record` or `replay`.
pub const ENV_CASSETTE_MODE: &str = "SYSKNIFE_CASSETTE_MODE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CassetteMode {
    Record,
    Replay,
}

impl CassetteMode {
    pub fn parse(raw: &str) -> Result<Self, CassetteError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "record" => Ok(Self::Record),
            "replay" => Ok(Self::Replay),
            other => Err(CassetteError::UnknownMode(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CassetteError {
    #[error("unknown cassette mode {0:?}; expected \"record\" or \"replay\"")]
    UnknownMode(String),

    #[error(
        "cassette {path} has version {found}, but this binary understands {understood}; \
         re-record it or use a matching build"
    )]
    UnsupportedVersion {
        path: PathBuf,
        found: u32,
        understood: u32,
    },

    #[error("cannot replay: no cassette at {0}")]
    Missing(PathBuf),

    #[error("cassette {path} is not readable: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cassette {path} is not valid JSON: {source}")]
    Malformed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// One recorded call. The key already carries the surface; it is repeated here
/// so a human reading the file can tell entries apart without hashing anything.
///
/// Exactly one of `output` and `rejection` is present. A cassette that stored
/// only successes could not reproduce a retry: the planner appends a correction
/// and re-asks after a rejected tool call, so the only call recorded was the
/// *second* one, and a replay starting from the first missed it and then missed
/// the identical re-ask. Storing the rejection makes the whole exchange replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    surface: String,
    /// The successful completion. Absent when the call was rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output: Option<Completion>,
    /// The refusal, when the provider rejected the request. Absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rejection: Option<RecordedRejection>,
    /// Per-component digests of the call this entry was recorded for.
    ///
    /// The key is a single hash over `(surface, system, messages, tools,
    /// max_tokens)`, which is all a *lookup* needs and all a *miss* used to be
    /// able to report: one 64-hex digest naming none of its inputs. That makes
    /// the obvious diagnostic — diff what was recorded against what the replay
    /// built — impossible, because nothing comparable is stored (#182).
    ///
    /// `Option` so cassettes recorded before this field stay loadable; a miss
    /// against one of those simply falls back to the old, vaguer message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fingerprint: Option<CallFingerprint>,
}

/// A provider refusal that is a property of the request, so replaying it is
/// honest rather than a cached flake.
///
/// `kind` is the variant name, kept so the replayed error is the same shape the
/// live one had. It matters: `is_retryable` and `is_invalid_tool_call` both
/// branch on the error, and a replay that reproduced the message but not the
/// variant would take a different path through the retry loop than the run it
/// claims to reproduce.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordedRejection {
    kind: String,
    message: String,
}

impl RecordedRejection {
    fn of(error: &ProviderError) -> Option<Self> {
        let kind = match error {
            ProviderError::Request(_) => "request",
            ProviderError::Parse(_) => "parse",
            // Nothing else can carry an invalid-tool-call rejection: no adapter
            // builds `Http`, and `Auth`/`RateLimit`/`CassetteMiss` are excluded
            // by `is_invalid_tool_call` itself.
            _ => return None,
        };
        Some(Self {
            kind: kind.to_string(),
            message: match error {
                ProviderError::Request(m) | ProviderError::Parse(m) => m.clone(),
                _ => return None,
            },
        })
    }

    fn to_error(&self) -> ProviderError {
        match self.kind.as_str() {
            "parse" => ProviderError::Parse(self.message.clone()),
            // "request" and anything a newer writer invents. Falling back to the
            // broader variant keeps an unknown kind replayable and retryable
            // rather than turning it into a silent success.
            _ => ProviderError::Request(self.message.clone()),
        }
    }
}

/// Whether a failure may be written to the cassette.
///
/// Exactly the failures the planner corrects and re-asks about — see
/// [`ProviderError::is_invalid_tool_call`] for why the two sets are one set.
/// Those are a deterministic function of the same bytes the key hashes, just
/// like a success.
///
/// Everything else describes the moment rather than the request: a 429 is load,
/// a timeout is timing, a 5xx is the far side having a bad day. Recording any of
/// them would bake a flake into the file and hand it back for ever.
fn recordable_rejection(error: &ProviderError) -> Option<RecordedRejection> {
    if !error.is_invalid_tool_call() {
        return None;
    }
    RecordedRejection::of(error)
}

/// Component digests of one call, enough to locate *where* two calls diverge
/// without storing the prompts or the conversation itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CallFingerprint {
    system: String,
    tools: String,
    max_tokens: u32,
    /// One digest per message, in order, so a divergence can be reported as an
    /// index rather than as "something differs".
    messages: Vec<String>,
}

impl CallFingerprint {
    fn of(system: &str, messages: &[Message], tools: &[ToolDefinition], max_tokens: u32) -> Self {
        Self {
            system: sha256_hex(system.as_bytes()),
            tools: sha256_hex(serde_json::to_string(tools).unwrap_or_default().as_bytes()),
            max_tokens,
            messages: messages
                .iter()
                .map(|m| sha256_hex(serde_json::to_string(m).unwrap_or_default().as_bytes()))
                .collect(),
        }
    }

    /// Index of the first message that differs, or `None` if one is a prefix of
    /// the other.
    fn first_divergent_message(&self, other: &Self) -> Option<usize> {
        self.messages
            .iter()
            .zip(&other.messages)
            .position(|(a, b)| a != b)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Meta {
    /// Every `provider/model` this file has recorded against.
    #[serde(default)]
    surfaces: BTreeSet<String>,
    /// Every distinct system prompt hash seen. A set, not a scalar: the prompt
    /// legitimately differs by distro family and by user preferences, so one
    /// cassette can hold several.
    #[serde(default)]
    system_prompt_sha256: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Document {
    version: u32,
    #[serde(default)]
    meta: Meta,
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
}

/// Reads only the version, so a format this binary does not understand is
/// reported as a version mismatch rather than as malformed JSON. Without this,
/// a future entry shape would surface as "not valid JSON" and send the reader
/// looking for corruption instead of for the right build.
#[derive(Deserialize)]
struct VersionProbe {
    version: u32,
}

/// Tally of what a replay actually did. Read by the harness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub hits: u64,
    pub misses: u64,
}

#[derive(Debug)]
pub struct Cassette {
    path: PathBuf,
    ledger_path: PathBuf,
    mode: CassetteMode,
    state: Mutex<Document>,
    tally: Mutex<Tally>,
}

/// Build a cassette from the environment, if one was asked for.
///
/// `SYSKNIFE_CASSETTE` set without `SYSKNIFE_CASSETTE_MODE` is an error rather
/// than a no-op. Silently ignoring it would send a run that was meant to be
/// hermetic straight to the live model, and the only symptom would be the bill.
pub fn from_env() -> Result<Option<Cassette>, String> {
    let path = match std::env::var(ENV_CASSETTE) {
        Ok(p) if !p.trim().is_empty() => p,
        _ => return Ok(None),
    };
    let raw_mode = std::env::var(ENV_CASSETTE_MODE).map_err(|_| {
        format!(
            "{ENV_CASSETTE} is set to {path:?} but {ENV_CASSETTE_MODE} is not; \
             set it to \"record\" or \"replay\""
        )
    })?;
    let mode = CassetteMode::parse(&raw_mode).map_err(|e| e.to_string())?;
    Cassette::open(&path, mode)
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Where the ledger for a given cassette lives.
fn ledger_path_for(cassette: &Path) -> PathBuf {
    let mut name = cassette.file_name().unwrap_or_default().to_os_string();
    name.push(".replay-log.jsonl");
    cassette.with_file_name(name)
}

impl Cassette {
    /// Open a cassette, loading an existing file when there is one.
    ///
    /// `record` resumes an existing file instead of truncating it, so an
    /// interrupted recording does not throw away the calls already paid for.
    pub fn open(path: impl AsRef<Path>, mode: CassetteMode) -> Result<Self, CassetteError> {
        let path = path.as_ref().to_path_buf();
        let ledger_path = ledger_path_for(&path);

        let document = if path.exists() {
            let raw = std::fs::read_to_string(&path).map_err(|source| CassetteError::Io {
                path: path.clone(),
                source,
            })?;
            // Version first, so a mismatch always wins over a shape complaint.
            let probe: VersionProbe =
                serde_json::from_str(&raw).map_err(|source| CassetteError::Malformed {
                    path: path.clone(),
                    source,
                })?;
            if probe.version > CASSETTE_VERSION {
                return Err(CassetteError::UnsupportedVersion {
                    path,
                    found: probe.version,
                    understood: CASSETTE_VERSION,
                });
            }
            serde_json::from_str(&raw).map_err(|source| CassetteError::Malformed {
                path: path.clone(),
                source,
            })?
        } else if mode == CassetteMode::Replay {
            // Replay cannot invent a recording, and an empty one would let every
            // story "pass" by missing. Fail at open instead.
            return Err(CassetteError::Missing(path));
        } else {
            Document {
                version: CASSETTE_VERSION,
                ..Document::default()
            }
        };

        // Under replay the ledger *is* the evidence, so prove it can be written
        // now rather than discovering per call that it cannot. A read-only
        // checkout used to produce a run whose every call replayed correctly and
        // whose audit then reported "served 0 calls", sending the reader after a
        // missing cassette instead of a missing write permission.
        if mode == CassetteMode::Replay {
            if let Some(parent) = ledger_path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|source| CassetteError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&ledger_path)
                .map_err(|source| CassetteError::Io {
                    path: ledger_path.clone(),
                    source,
                })?;
        }

        Ok(Self {
            path,
            ledger_path,
            mode,
            state: Mutex::new(document),
            tally: Mutex::new(Tally::default()),
        })
    }

    /// Where the per-call replay ledger is written.
    pub fn ledger_path(&self) -> &Path {
        &self.ledger_path
    }

    pub fn mode(&self) -> CassetteMode {
        self.mode
    }

    pub fn tally(&self) -> Tally {
        *self.tally.lock().expect("cassette tally poisoned")
    }

    /// Read a ledger written by an earlier process and total it up.
    ///
    /// An absent ledger totals to zero rather than erroring: a harness asserting
    /// `hits > 0` then fails on the real problem ("nothing replayed") instead of
    /// on a missing-file message that reads like a setup fault.
    pub fn read_ledger(path: impl AsRef<Path>) -> Result<Tally, CassetteError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Tally::default());
        }
        let raw = std::fs::read_to_string(path).map_err(|source| CassetteError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut tally = Tally::default();
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            let entry: serde_json::Value =
                serde_json::from_str(line).map_err(|source| CassetteError::Malformed {
                    path: path.to_path_buf(),
                    source,
                })?;
            match entry.get("outcome").and_then(|v| v.as_str()) {
                Some("hit") => tally.hits += 1,
                Some("miss") => tally.misses += 1,
                // An unknown outcome is counted as a miss rather than ignored: a
                // line this build cannot interpret must not read as success.
                _ => tally.misses += 1,
            }
        }
        Ok(tally)
    }

    /// The recorded outcome for `key`, which may be a refusal.
    ///
    /// `Some(Err(..))` is a hit, not a miss: the recording says this exact
    /// request was rejected, and handing that back is what lets the caller's
    /// retry take the same path it took live.
    fn lookup(&self, key: &str) -> Option<Result<Completion, ProviderError>> {
        let state = self.state.lock().expect("cassette state poisoned");
        let entry = state.entries.get(key)?;
        match (&entry.output, &entry.rejection) {
            (Some(output), _) => Some(Ok(output.clone())),
            (None, Some(r)) => Some(Err(r.to_error())),
            // An entry with neither is a file someone edited by hand. Treating it
            // as a miss reports the divergence instead of serving an empty plan
            // that would read as the model having nothing to say.
            (None, None) => None,
        }
    }

    /// True when this exact system prompt was never recorded, which is the usual
    /// cause of a whole suite missing at once.
    fn prompt_is_unknown(&self, prompt_sha: &str) -> bool {
        let state = self.state.lock().expect("cassette state poisoned");
        !state.meta.system_prompt_sha256.contains(prompt_sha)
    }

    /// Persist one recorded call, with the component digests that let a later
    /// miss say which part of the call diverged. See [`CallFingerprint`].
    fn store(
        &self,
        key: String,
        surface: &str,
        prompt_sha: &str,
        output: Completion,
        fingerprint: Option<CallFingerprint>,
    ) -> Result<(), CassetteError> {
        self.store_entry(key, surface, prompt_sha, Some(output), None, fingerprint)
    }

    /// Persist a provider refusal. See [`recordable_rejection`] for which ones.
    fn store_rejection(
        &self,
        key: String,
        surface: &str,
        prompt_sha: &str,
        rejection: RecordedRejection,
        fingerprint: Option<CallFingerprint>,
    ) -> Result<(), CassetteError> {
        self.store_entry(key, surface, prompt_sha, None, Some(rejection), fingerprint)
    }

    fn store_entry(
        &self,
        key: String,
        surface: &str,
        prompt_sha: &str,
        output: Option<Completion>,
        rejection: Option<RecordedRejection>,
        fingerprint: Option<CallFingerprint>,
    ) -> Result<(), CassetteError> {
        {
            let mut state = self.state.lock().expect("cassette state poisoned");
            state.meta.surfaces.insert(surface.to_string());
            state
                .meta
                .system_prompt_sha256
                .insert(prompt_sha.to_string());
            // A file this binary has written is a v2 file, even when it was
            // opened from a v1 one. Leaving the stamp at 1 while writing an
            // entry only v2 understands is the exact silent-half-read the
            // version field exists to prevent.
            state.version = CASSETTE_VERSION;
            state.entries.insert(
                key.clone(),
                Entry {
                    surface: surface.to_string(),
                    output,
                    rejection,
                    fingerprint,
                },
            );
        }
        // Roll back if it never reached disk, so "in memory" and "durable" cannot
        // diverge. Today the caller aborts on this error anyway, but an entry that
        // is visible to `lookup` while absent from the file is a recording that
        // believes it captured a call it did not.
        if let Err(e) = self.persist() {
            let mut state = self.state.lock().expect("cassette state poisoned");
            state.entries.remove(&key);
            return Err(e);
        }
        Ok(())
    }

    /// Write after every new entry, so an interrupted recording keeps the calls
    /// already paid for. Written to a temporary file in the same directory and
    /// renamed, so a crash mid-write cannot leave a truncated cassette that would
    /// later parse as "these calls were never recorded".
    fn persist(&self) -> Result<(), CassetteError> {
        // A bare filename yields Some(""), not None, and neither create_dir_all
        // nor NamedTempFile::new_in accepts "" meaningfully, so map both the empty
        // and the absent parent onto the current directory. Written as a filter so
        // the fallback is actually reachable rather than decorative.
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|source| CassetteError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let json = {
            let state = self.state.lock().expect("cassette state poisoned");
            serde_json::to_string_pretty(&*state).map_err(|source| CassetteError::Malformed {
                path: self.path.clone(),
                source,
            })?
        };
        let mut tmp =
            tempfile::NamedTempFile::new_in(parent).map_err(|source| CassetteError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        tmp.write_all(json.as_bytes())
            .and_then(|()| tmp.write_all(b"\n"))
            .map_err(|source| CassetteError::Io {
                path: self.path.clone(),
                source,
            })?;
        tmp.persist(&self.path).map_err(|e| CassetteError::Io {
            path: self.path.clone(),
            source: e.error,
        })?;

        // NamedTempFile creates at 0600 and the rename keeps it, which is wrong for
        // a cassette: it is a committed fixture holding model outputs, not a secret.
        // Recording inside a VM as root then left a 0600 root-owned file in the
        // synced tree, and every later `ubuntu-vm.sh sync` failed trying to update
        // it. Failure to relax the mode is not fatal on its own.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Err(e) =
                std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o644))
            {
                eprintln!(
                    "[sysknife-brain] could not relax cassette permissions on {}: {e}",
                    self.path.display()
                );
            }
        }
        Ok(())
    }

    fn note(&self, outcome: &str, surface: &str, key: &str) {
        {
            let mut tally = self.tally.lock().expect("cassette tally poisoned");
            match outcome {
                "hit" => tally.hits += 1,
                _ => tally.misses += 1,
            }
        }
        if self.mode != CassetteMode::Replay {
            // Record mode's evidence is the cassette itself.
            return;
        }
        // Writability was proven at open, so a failure here is a change of
        // circumstances (disk full, the file removed underneath us) rather than a
        // misconfiguration. It must be said out loud: losing the line for a miss
        // while keeping earlier hits is the one combination that makes the audit
        // read "served N, 0 misses" on a run that in fact missed.
        let line = serde_json::json!({"outcome": outcome, "surface": surface, "key": key});
        let appended = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.ledger_path)
            .and_then(|mut f| writeln!(f, "{line}"));
        if let Err(e) = appended {
            eprintln!(
                "[sysknife-brain] cassette ledger write failed at {}: {e} \
                 -- this replay's evidence is incomplete and its result is not trustworthy",
                self.ledger_path.display()
            );
        }
    }
}

impl Cassette {
    /// Explain a replay miss by comparing the call against what was recorded.
    ///
    /// A miss is a hash mismatch, and a hash names none of its inputs — so the
    /// bare message could only ever say "no recorded output", which is true and
    /// useless. This walks the recorded entries for the same surface and reports
    /// the most specific thing it can prove:
    ///
    /// - the system prompt changed (every call will miss; re-record);
    /// - the tool schema changed (likewise);
    /// - or the conversation matched up to message N and diverged there, which
    ///   is the signature of a volatile tool result: turn 1 replays, turn 2
    ///   cannot, because something in between differs run to run (#182).
    fn diagnose_miss(
        &self,
        surface: &str,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> String {
        let want = CallFingerprint::of(system, messages, tools, max_tokens);
        let state = self.state.lock().expect("cassette state poisoned");

        let recorded: Vec<&CallFingerprint> = state
            .entries
            .values()
            .filter(|e| e.surface == surface)
            .filter_map(|e| e.fingerprint.as_ref())
            .collect();

        if recorded.is_empty() {
            return format!(
                "no recorded output for surface {surface} in {}; re-record with {}=record",
                self.path.display(),
                ENV_CASSETTE_MODE
            );
        }

        if !recorded.iter().any(|f| f.system == want.system) {
            return format!(
                "the system prompt changed, so every call will miss; re-record with {}=record",
                ENV_CASSETTE_MODE
            );
        }
        if !recorded.iter().any(|f| f.tools == want.tools) {
            return format!(
                "the tool schema changed, so every call will miss; re-record with {}=record",
                ENV_CASSETTE_MODE
            );
        }

        // Same prompt and tools: the conversation itself diverged. Report the
        // deepest match, since that is the turn boundary where determinism broke.
        let deepest = recorded
            .iter()
            .filter(|f| f.system == want.system && f.tools == want.tools)
            .filter_map(|f| f.first_divergent_message(&want))
            .max();

        match deepest {
            // Message 0 is the user's intent. Diverging there means this is a
            // different conversation, not a broken one: nothing was ever
            // recorded for it. Reporting it as a mid-run divergence sent the
            // reader hunting a volatile tool result that does not exist — which
            // is exactly what it did on the first replay after this landed.
            Some(0) => format!(
                "no recorded output for this intent in {}. The prompt and tools match, so \
                 the cassette is current — this particular request was never recorded. A \
                 recording made before cassette v2 is the usual reason: only successes \
                 were kept, so an intent whose first call the provider rejected left the \
                 corrected retry behind and nothing to start it from. Re-record with \
                 {}=record if it should be covered.",
                self.path.display(),
                ENV_CASSETTE_MODE
            ),
            Some(index) => format!(
                "the conversation diverged at message {index}: the intent and the turns \
                 before it replay, this one does not. That is the signature of a volatile \
                 tool result — a timestamp, a transaction id, or live system state folded \
                 into the call key. See issue #182."
            ),
            None => format!(
                "no recorded output for this call in {}; the prompt and tools match, so \
                 the conversation reached a turn that was never recorded. Re-record with \
                 {}=record",
                self.path.display(),
                ENV_CASSETTE_MODE
            ),
        }
    }
}

/// The stable key for one call.
///
/// Field order is fixed by construction and every nested type serialises in
/// declaration order, so the digest is reproducible across runs and machines.
fn call_key(
    surface: &str,
    system: &str,
    messages: &[Message],
    tools: &[ToolDefinition],
    max_tokens: u32,
) -> String {
    let canonical = serde_json::json!({
        "surface": surface,
        "system": system,
        "messages": messages,
        "tools": tools,
        "max_tokens": max_tokens,
    })
    .to_string();
    format!("{surface}:{}", sha256_hex(canonical.as_bytes()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Wraps another provider in record/replay behaviour.
pub struct CassetteProvider {
    inner: Box<dyn LlmProvider>,
    cassette: Cassette,
    surface: String,
}

impl CassetteProvider {
    pub fn new(
        inner: Box<dyn LlmProvider>,
        cassette: Cassette,
        surface: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            cassette,
            surface: surface.into(),
        }
    }

    pub fn cassette(&self) -> &Cassette {
        &self.cassette
    }
}

#[async_trait]
impl LlmProvider for CassetteProvider {
    async fn complete(
        &self,
        system: &str,
        messages: &[Message],
        tools: &[ToolDefinition],
        max_tokens: u32,
    ) -> Result<Completion, ProviderError> {
        let key = call_key(&self.surface, system, messages, tools, max_tokens);

        if let Some(outcome) = self.cassette.lookup(&key) {
            // A recorded refusal is a hit. The caller's retry then takes the same
            // path it took live, which is the only way an exchange that needed a
            // retry replays at all.
            self.cassette.note("hit", &self.surface, &key);
            return outcome;
        }

        if self.cassette.mode == CassetteMode::Replay {
            self.cassette.note("miss", &self.surface, &key);
            let prompt_sha = sha256_hex(system.as_bytes());
            // The prompt check first: it is provable from `meta` alone and
            // explains every call missing at once, which no per-call comparison
            // should be allowed to contradict.
            let detail = if self.cassette.prompt_is_unknown(&prompt_sha) {
                format!(
                    "the system prompt changed (sha256 {prompt_sha} was never recorded in {}), \
                     so every call will miss; re-record after a prompt change",
                    self.cassette.path.display()
                )
            } else {
                self.cassette
                    .diagnose_miss(&self.surface, system, messages, tools, max_tokens)
            };
            return Err(ProviderError::CassetteMiss(detail));
        }

        // Record: pay for the call once, then keep it.
        let outcome = self
            .inner
            .complete(system, messages, tools, max_tokens)
            .await;
        // The fingerprint's `system` field is the same sha256 `prompt_sha` needs;
        // compute it once and reuse it rather than hashing the (tens-of-KB)
        // system prompt twice for one stored call.
        let fingerprint = CallFingerprint::of(system, messages, tools, max_tokens);
        let prompt_sha = fingerprint.system.clone();
        let write_failed = |e| ProviderError::CassetteMiss(format!("cannot write cassette: {e}"));

        match outcome {
            Ok(output) => {
                self.cassette
                    .store(
                        key,
                        &self.surface,
                        &prompt_sha,
                        output.clone(),
                        Some(fingerprint),
                    )
                    .map_err(write_failed)?;
                Ok(output)
            }
            Err(error) => {
                if let Some(rejection) = recordable_rejection(&error) {
                    self.cassette
                        .store_rejection(
                            key,
                            &self.surface,
                            &prompt_sha,
                            rejection,
                            Some(fingerprint),
                        )
                        .map_err(write_failed)?;
                }
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ContentBlock, StopReason};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn text_completion(text: &str) -> Completion {
        Completion {
            content: vec![ContentBlock::Text { text: text.into() }],
            stop_reason: StopReason::EndTurn,
        }
    }

    fn first_text(c: &Completion) -> String {
        match c.content.first() {
            Some(ContentBlock::Text { text }) => text.clone(),
            other => panic!("expected a text block, got {other:?}"),
        }
    }

    /// Counts its calls and echoes the tail of the conversation, so a replayed
    /// answer is distinguishable from a fresh one.
    struct Counting {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl LlmProvider for Counting {
        async fn complete(
            &self,
            _system: &str,
            messages: &[Message],
            _tools: &[ToolDefinition],
            _max_tokens: u32,
        ) -> Result<Completion, ProviderError> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(text_completion(&format!("live#{n}:{}", messages.len())))
        }
    }

    /// Fails the test if the network is touched at all.
    struct Exploding;

    #[async_trait]
    impl LlmProvider for Exploding {
        async fn complete(
            &self,
            _system: &str,
            _messages: &[Message],
            _tools: &[ToolDefinition],
            _max_tokens: u32,
        ) -> Result<Completion, ProviderError> {
            panic!("replay must never call the underlying model");
        }
    }

    fn counting() -> (Box<dyn LlmProvider>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Box::new(Counting {
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }

    fn msgs(text: &str) -> Vec<Message> {
        vec![Message::user_text(text)]
    }

    const SURFACE: &str = "groq/openai-gpt-oss-120b";

    /// A `CassetteProvider` in `Record` mode against `SURFACE`. Most tests below
    /// only vary the inner provider and the path; this and [`replayer`] collapse
    /// that repeated four-line construction to one call.
    fn recorder(inner: Box<dyn LlmProvider>, path: &Path) -> CassetteProvider {
        CassetteProvider::new(
            inner,
            Cassette::open(path, CassetteMode::Record).unwrap(),
            SURFACE,
        )
    }

    /// A `CassetteProvider` in `Replay` mode against `SURFACE`. See [`recorder`].
    fn replayer(inner: Box<dyn LlmProvider>, path: &Path) -> CassetteProvider {
        CassetteProvider::new(
            inner,
            Cassette::open(path, CassetteMode::Replay).unwrap(),
            SURFACE,
        )
    }

    #[tokio::test]
    async fn record_calls_through_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, calls) = counting();
        let p = recorder(inner, &path);

        let out = p.complete("sys", &msgs("hi"), &[], 100).await.unwrap();
        assert_eq!(first_text(&out), "live#1:1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(path.exists(), "recording must persist for a later replay");
    }

    #[tokio::test]
    async fn replay_answers_without_calling_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, _) = counting();
        let rec = recorder(inner, &path);
        rec.complete("sys", &msgs("hi"), &[], 100).await.unwrap();
        drop(rec);

        let rep = replayer(Box::new(Exploding), &path);
        let out = rep.complete("sys", &msgs("hi"), &[], 100).await.unwrap();
        assert_eq!(first_text(&out), "live#1:1", "must be the recorded answer");
        assert_eq!(rep.cassette().tally().hits, 1);
    }

    #[tokio::test]
    async fn replay_miss_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, _) = counting();
        let rec = recorder(inner, &path);
        rec.complete("sys", &msgs("recorded"), &[], 100)
            .await
            .unwrap();
        drop(rec);

        let rep = replayer(Box::new(Exploding), &path);
        let err = rep
            .complete("sys", &msgs("never-recorded"), &[], 100)
            .await
            .expect_err("a miss must not be answered");
        assert!(
            format!("{err}").contains("cassette"),
            "the error must name the cassette, got: {err}"
        );
        assert_eq!(rep.cassette().tally().misses, 1);
    }

    #[tokio::test]
    async fn record_dedups_identical_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, calls) = counting();
        let p = recorder(inner, &path);

        let a = p.complete("sys", &msgs("same"), &[], 100).await.unwrap();
        let b = p.complete("sys", &msgs("same"), &[], 100).await.unwrap();
        assert_eq!(first_text(&a), first_text(&b));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "an identical call must be served from the cache, not paid for twice"
        );
    }

    #[tokio::test]
    async fn a_cassette_recorded_on_one_model_does_not_answer_for_another() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, _) = counting();
        let rec = CassetteProvider::new(
            inner,
            Cassette::open(&path, CassetteMode::Record).unwrap(),
            "groq/model-a",
        );
        rec.complete("sys", &msgs("hi"), &[], 100).await.unwrap();
        drop(rec);

        let rep = CassetteProvider::new(
            Box::new(Exploding),
            Cassette::open(&path, CassetteMode::Replay).unwrap(),
            "groq/model-b",
        );
        rep.complete("sys", &msgs("hi"), &[], 100)
            .await
            .expect_err("a different model must miss, not inherit the recording");
    }

    #[tokio::test]
    async fn tools_and_max_tokens_participate_in_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, _) = counting();
        let rec = recorder(inner, &path);
        rec.complete("sys", &msgs("hi"), &[], 100).await.unwrap();
        drop(rec);

        let rep = replayer(Box::new(Exploding), &path);
        rep.complete("sys", &msgs("hi"), &[], 999)
            .await
            .expect_err("a different max_tokens is a different call");

        let tool = ToolDefinition {
            name: "propose_plan".into(),
            description: "d".into(),
            input_schema: serde_json::json!({}),
        };
        rep.complete("sys", &msgs("hi"), &[tool], 100)
            .await
            .expect_err("a different tool set is a different call");
    }

    #[tokio::test]
    async fn the_ledger_records_hits_and_misses_for_the_harness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, _) = counting();
        let rec = recorder(inner, &path);
        rec.complete("sys", &msgs("known"), &[], 100).await.unwrap();
        drop(rec);

        let rep = replayer(Box::new(Exploding), &path);
        rep.complete("sys", &msgs("known"), &[], 100).await.unwrap();
        let _ = rep.complete("sys", &msgs("unknown"), &[], 100).await; // swallowed
        let ledger = rep.cassette().ledger_path().to_path_buf();
        drop(rep);

        let tally = Cassette::read_ledger(&ledger).unwrap();
        assert_eq!(
            tally,
            Tally { hits: 1, misses: 1 },
            "the ledger is how a harness proves a replay happened and was clean"
        );
    }

    #[tokio::test]
    async fn an_unknown_cassette_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        std::fs::write(
            &path,
            serde_json::json!({"version": 999, "meta": {}, "entries": {}}).to_string(),
        )
        .unwrap();
        let err = Cassette::open(&path, CassetteMode::Replay)
            .expect_err("a future format must not be half-read");
        assert!(matches!(err, CassetteError::UnsupportedVersion { .. }));
    }

    #[tokio::test]
    async fn a_cassette_from_an_older_format_still_replays() {
        // v2 only added optional fields. Refusing v1 would have discarded three
        // committed recordings — and the whole point of committing them is that
        // they outlive the commit that made them.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let msgs = msgs("hi");
        let key = call_key(SURFACE, "SYS", &msgs, &[], 100);
        std::fs::write(
            &path,
            serde_json::json!({
                "version": 1,
                "meta": {"surfaces": [SURFACE], "system_prompt_sha256": [sha256_hex(b"SYS")]},
                "entries": {key: {"surface": SURFACE, "output": text_completion("v1 answer")}},
            })
            .to_string(),
        )
        .unwrap();

        let rep = replayer(Box::new(Exploding), &path);
        let out = rep.complete("SYS", &msgs, &[], 100).await.unwrap();
        assert_eq!(
            serde_json::to_string(&out).unwrap(),
            serde_json::to_string(&text_completion("v1 answer")).unwrap()
        );
    }

    #[tokio::test]
    async fn writing_to_a_v1_cassette_restamps_it_as_v2() {
        // The stamp has to move with the shape. A v1 header over an entry only v2
        // can read is precisely the silent half-read the version field prevents.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        std::fs::write(
            &path,
            serde_json::json!({"version": 1, "meta": {}, "entries": {}}).to_string(),
        )
        .unwrap();

        let (inner, _) = counting();
        let rec = recorder(inner, &path);
        rec.complete("SYS", &msgs("hi"), &[], 100).await.unwrap();

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["version"], 2, "a file this binary wrote is a v2 file");
    }

    #[tokio::test]
    async fn a_changed_system_prompt_misses_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, _) = counting();
        let rec = recorder(inner, &path);
        rec.complete("prompt version one", &msgs("hi"), &[], 100)
            .await
            .unwrap();
        drop(rec);

        let rep = replayer(Box::new(Exploding), &path);
        let err = rep
            .complete("prompt version two", &msgs("hi"), &[], 100)
            .await
            .expect_err("a changed prompt invalidates the recording");
        assert!(
            format!("{err}").contains("system prompt"),
            "a wall of misses must be diagnosable as a prompt change, got: {err}"
        );
    }

    #[tokio::test]
    async fn record_resumes_an_existing_cassette_instead_of_clobbering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, calls) = counting();
        let first = recorder(inner, &path);
        first.complete("sys", &msgs("one"), &[], 100).await.unwrap();
        drop(first);

        let (inner2, calls2) = counting();
        let second = recorder(inner2, &path);
        // Already recorded: must be served from the file, not paid for again.
        second
            .complete("sys", &msgs("one"), &[], 100)
            .await
            .unwrap();
        second
            .complete("sys", &msgs("two"), &[], 100)
            .await
            .unwrap();
        drop(second);

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            calls2.load(Ordering::SeqCst),
            1,
            "only the new call is paid for"
        );

        let rep = replayer(Box::new(Exploding), &path);
        rep.complete("sys", &msgs("one"), &[], 100).await.unwrap();
        rep.complete("sys", &msgs("two"), &[], 100).await.unwrap();
        assert_eq!(
            rep.cassette().tally().hits,
            2,
            "both calls survived the resume"
        );
    }

    /// Env-var tests share the process, so they take a lock like the ones in
    /// `config.rs` do.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn no_cassette_is_configured_by_default() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var(ENV_CASSETTE);
            std::env::remove_var(ENV_CASSETTE_MODE);
        }
        assert!(from_env().expect("absent is not an error").is_none());
    }

    #[test]
    fn a_cassette_path_without_a_mode_is_refused() {
        // Silently ignoring it would send a run meant to be hermetic to the live
        // model, and the only symptom would be the bill.
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(ENV_CASSETTE, "/tmp/does-not-matter.json");
            std::env::remove_var(ENV_CASSETTE_MODE);
        }
        let err = from_env().expect_err("a path without a mode must not be ignored");
        unsafe { std::env::remove_var(ENV_CASSETTE) };
        assert!(
            err.contains(ENV_CASSETTE_MODE),
            "must name the missing var: {err}"
        );
    }

    #[test]
    fn an_unknown_mode_is_refused() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(ENV_CASSETTE, "/tmp/does-not-matter.json");
            std::env::set_var(ENV_CASSETTE_MODE, "playback");
        }
        let err = from_env().expect_err("only record and replay are modes");
        unsafe {
            std::env::remove_var(ENV_CASSETTE);
            std::env::remove_var(ENV_CASSETTE_MODE);
        }
        assert!(err.contains("playback"), "must quote the bad value: {err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_recorded_cassette_is_group_and_world_readable() {
        // It is a committed fixture, not a secret. NamedTempFile's 0600 default
        // used to survive the rename, and a root-owned 0600 file in the synced
        // tree broke every later `ubuntu-vm.sh sync`.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let (inner, _) = counting();
        let p = recorder(inner, &path);
        p.complete("sys", &msgs("hi"), &[], 100).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "cassette should be 0644, got {mode:o}");
    }

    #[test]
    fn replay_refuses_to_start_when_it_cannot_write_its_ledger() {
        // The ledger is the evidence a replay happened. A read-only checkout used
        // to yield a run whose calls all replayed correctly and whose audit then
        // said "served 0 calls", pointing the reader at a missing cassette rather
        // than a missing write permission.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        std::fs::write(
            &path,
            serde_json::json!({"version": 1, "meta": {}, "entries": {}}).to_string(),
        )
        .unwrap();

        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        let outcome = Cassette::open(&path, CassetteMode::Replay);

        // Restore before asserting so the tempdir can always clean itself up.
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        // Skipped rather than failed when running as root, which ignores the mode
        // bits entirely; asserting there would be testing the kernel, not this.
        if running_as_root() {
            return;
        }
        assert!(
            matches!(outcome, Err(CassetteError::Io { .. })),
            "an unwritable ledger must fail at open, got {outcome:?}"
        );
    }

    /// Real uid from /proc, to avoid a libc dependency for one call in one test.
    /// An unreadable or unparseable status file is treated as non-root, which
    /// keeps the assertion active rather than skipping it on a guess.
    fn running_as_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find(|l| l.starts_with("Uid:"))?
                    .split_whitespace()
                    .nth(1)?
                    .parse::<u32>()
                    .ok()
            })
            .is_some_and(|uid| uid == 0)
    }

    #[tokio::test]
    async fn replaying_a_missing_cassette_fails_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let err = Cassette::open(dir.path().join("absent.json"), CassetteMode::Replay)
            .expect_err("replay cannot invent a cassette");
        assert!(matches!(err, CassetteError::Missing(_)));
    }

    // ── Recording a rejection ────────────────────────────────────────────────
    //
    // The planner retries a rejected tool call with a correction appended, so a
    // story that needs the retry records only the *second* call. A replay starts
    // from the first, misses, and — because a `CassetteMiss` carries none of the
    // markers that trigger a correction — retries the identical bytes and misses
    // again. That is exactly how story 101 came back 79/79 live and 78/79 on its
    // own twin, with two misses for one story.
    //
    // A cassette that stores only successes cannot reproduce any retry. These
    // tests pin the other half.

    /// Groq's rejection as it actually reaches us.
    ///
    /// Not `ProviderError::Http`: no adapter constructs that variant. A 400 is
    /// classified `StatusClass::Other` and becomes `Request`. Building the test
    /// double out of `Http` made every assertion below pass against a shape the
    /// system cannot produce.
    fn tool_use_failed() -> ProviderError {
        ProviderError::Request(
            "{\"error\":{\"message\":\"Failed to call a function. Please adjust your prompt.\",\
             \"type\":\"invalid_request_error\",\"code\":\"tool_use_failed\"}}"
                .into(),
        )
    }

    /// A provider that rejects the first call the way Groq rejects a tool call
    /// naming a tool that is not in the request, then answers.
    struct RejectsThenAnswers {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl LlmProvider for RejectsThenAnswers {
        async fn complete(
            &self,
            _system: &str,
            _messages: &[Message],
            _tools: &[ToolDefinition],
            _max_tokens: u32,
        ) -> Result<Completion, ProviderError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(tool_use_failed());
            }
            Ok(text_completion("recovered"))
        }
    }

    #[test]
    fn the_recorder_keeps_exactly_what_the_retry_corrects() {
        // The two sets have to be one set. A recorder narrower than the retrier
        // leaves a retried run unreplayable — which is the bug this fixes; a
        // recorder wider than it serves a transient failure back for ever.
        let cases = [
            tool_use_failed(),
            ProviderError::Request(
                "attempted to call tool 'json' which was not in request.tools".into(),
            ),
            ProviderError::Parse("tool_use_failed in a malformed payload".into()),
            ProviderError::Request("connection reset by peer".into()),
            ProviderError::RateLimit("Rate limit reached".into()),
            ProviderError::Auth("bad key".into()),
            ProviderError::Parse("truncated json".into()),
            ProviderError::CassetteMiss("no recording for tool_use_failed".into()),
        ];
        for error in cases {
            assert_eq!(
                recordable_rejection(&error).is_some(),
                error.is_invalid_tool_call(),
                "recorder and retrier disagree about {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_rejected_request_is_recorded_and_replayed_as_the_same_rejection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let calls = Arc::new(AtomicUsize::new(0));

        // Record: the provider rejects, and the rejection is kept.
        let rec = recorder(
            Box::new(RejectsThenAnswers {
                calls: Arc::clone(&calls),
            }),
            &path,
        );
        let live = rec.complete("SYS", &msgs("hi"), &[], 100).await;
        let live = live.expect_err("the double rejects the first call");
        assert!(live.is_invalid_tool_call());

        // Replay: the same rejection comes back, without touching the provider.
        let rep = replayer(Box::new(Exploding), &path);
        let replayed = rep
            .complete("SYS", &msgs("hi"), &[], 100)
            .await
            .expect_err("the recording says this request was rejected");
        assert!(
            matches!(replayed, ProviderError::Request(_)),
            "the variant must survive the round trip, not just the text: {replayed:?}"
        );
        assert!(
            replayed.is_invalid_tool_call(),
            "a replayed rejection must still trigger the correction: {replayed}"
        );
        assert!(
            replayed.is_retryable(),
            "…and must still be retryable, or the retry never happens: {replayed}"
        );
    }

    #[tokio::test]
    async fn replaying_a_recorded_rejection_counts_as_a_hit_not_a_miss() {
        // A miss fails the whole run by design. If a recorded rejection were
        // tallied as a miss, recording it would swap one red run for another.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let calls = Arc::new(AtomicUsize::new(0));

        let rec = recorder(Box::new(RejectsThenAnswers { calls }), &path);
        let _ = rec.complete("SYS", &msgs("hi"), &[], 100).await;

        let rep = replayer(Box::new(Exploding), &path);
        let _ = rep.complete("SYS", &msgs("hi"), &[], 100).await;
        let tally = Cassette::read_ledger(ledger_path_for(&path)).unwrap();
        assert_eq!(tally.hits, 1, "a recorded rejection is a hit");
        assert_eq!(tally.misses, 0);
    }

    #[tokio::test]
    async fn a_transient_failure_is_not_recorded() {
        // A 429 or a timeout says something about the moment, not about the
        // request. Recording one would bake a flake into the file and hand it
        // back on every replay for ever.
        struct AlwaysRateLimited;
        #[async_trait]
        impl LlmProvider for AlwaysRateLimited {
            async fn complete(
                &self,
                _s: &str,
                _m: &[Message],
                _t: &[ToolDefinition],
                _mt: u32,
            ) -> Result<Completion, ProviderError> {
                Err(ProviderError::RateLimit("Rate limit reached".into()))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let rec = recorder(Box::new(AlwaysRateLimited), &path);
        let _ = rec.complete("SYS", &msgs("hi"), &[], 100).await;

        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_default())
                .unwrap_or(serde_json::json!({"entries": {}}));
        assert_eq!(
            doc["entries"].as_object().map(|o| o.len()).unwrap_or(0),
            0,
            "a 429 must not be recorded: {doc}"
        );
    }
}

#[cfg(test)]
mod miss_diagnosis_tests {
    use super::*;
    use crate::provider::{ContentBlock, Message, StopReason};

    fn completion(text: &str) -> Completion {
        Completion {
            content: vec![ContentBlock::Text { text: text.into() }],
            stop_reason: StopReason::EndTurn,
        }
    }

    /// A replay miss used to report a 64-hex digest and nothing else, which is
    /// unactionable: the key is a hash of `(surface, system, messages, tools,
    /// max_tokens)` and the message identifying it names none of them. Issue #182
    /// asks to "diff the recorded messages against what a replay builds" — that is
    /// not possible against a file that stores only hashes, so the first fix is to
    /// make a miss say which component diverged.
    #[test]
    fn a_miss_caused_by_a_later_turn_names_the_diverging_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");

        // Record a two-turn conversation.
        let rec = Cassette::open(path.clone(), CassetteMode::Record).unwrap();
        let system = "SYSTEM";
        let turn1 = vec![Message::user_text("install vim; rm -rf /")];
        let turn2 = vec![
            Message::user_text("install vim; rm -rf /"),
            Message::user_text("Plan rejected: injected metacharacters."),
        ];
        for (msgs, out) in [(&turn1, "turn one"), (&turn2, "turn two")] {
            rec.store(
                call_key("p/m", system, msgs, &[], 100),
                "p/m",
                &sha256_hex(system.as_bytes()),
                completion(out),
                Some(CallFingerprint::of(system, msgs, &[], 100)),
            )
            .unwrap();
        }

        // Replay: turn 1 matches, turn 2's second message differs by one word —
        // the shape a volatile tool result produces.
        let replay = Cassette::open(path, CassetteMode::Replay).unwrap();
        assert!(
            replay
                .lookup(&call_key("p/m", system, &turn1, &[], 100))
                .is_some(),
            "turn 1 must still replay"
        );

        let drifted = vec![
            Message::user_text("install vim; rm -rf /"),
            Message::user_text("Plan rejected: injected metacharacter."),
        ];
        let diagnosis = replay.diagnose_miss("p/m", system, &drifted, &[], 100);
        assert!(
            diagnosis.contains("message 1"),
            "must name the diverging message index, got: {diagnosis}"
        );
        assert!(
            diagnosis.to_lowercase().contains("turn"),
            "must say the conversation diverged mid-run, got: {diagnosis}"
        );
    }

    /// Diverging at message 0 means a different *intent* — a conversation that
    /// was never recorded, not one that broke partway. The first real replay
    /// after this landed reported "diverged at message 0" for a story whose call
    /// simply errored during recording, which sends the reader hunting a
    /// volatile tool result that does not exist.
    #[test]
    fn an_unrecorded_intent_is_not_reported_as_a_mid_run_divergence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let rec = Cassette::open(path.clone(), CassetteMode::Record).unwrap();
        let system = "SYSTEM";
        let recorded = vec![Message::user_text("install vim")];
        rec.store(
            call_key("p/m", system, &recorded, &[], 100),
            "p/m",
            &sha256_hex(system.as_bytes()),
            completion("out"),
            Some(CallFingerprint::of(system, &recorded, &[], 100)),
        )
        .unwrap();

        let replay = Cassette::open(path, CassetteMode::Replay).unwrap();
        // A completely different first message: never recorded.
        let other = vec![Message::user_text("list the snaps")];
        let d = replay.diagnose_miss("p/m", system, &other, &[], 100);
        assert!(
            !d.contains("diverged at message"),
            "an unrecorded intent must not read as a mid-run divergence: {d}"
        );
        assert!(
            d.contains("never recorded"),
            "it must say the request was never recorded: {d}"
        );
    }

    /// The other shape: nothing about the conversation matches, because the
    /// system prompt or tools changed. That must NOT be reported as a mid-turn
    /// divergence — it is a re-record, not a volatile field.
    #[test]
    fn a_miss_caused_by_a_changed_prompt_is_not_blamed_on_a_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.json");
        let rec = Cassette::open(path.clone(), CassetteMode::Record).unwrap();
        let msgs = vec![Message::user_text("hello")];
        rec.store(
            call_key("p/m", "OLD SYSTEM", &msgs, &[], 100),
            "p/m",
            &sha256_hex(b"OLD SYSTEM"),
            completion("out"),
            Some(CallFingerprint::of("OLD SYSTEM", &msgs, &[], 100)),
        )
        .unwrap();

        let replay = Cassette::open(path, CassetteMode::Replay).unwrap();
        let diagnosis = replay.diagnose_miss("p/m", "NEW SYSTEM", &msgs, &[], 100);
        assert!(
            diagnosis.contains("system prompt"),
            "a changed prompt must be named as such, got: {diagnosis}"
        );
        assert!(
            !diagnosis.contains("message 0"),
            "must not blame a message when the prompt is what changed: {diagnosis}"
        );
    }
}
