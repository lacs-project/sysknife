// Tauri response types — mirror the structs in commands.rs exactly.
// All field names are camelCase because commands.rs uses #[serde(rename_all = "camelCase")].

export interface PlanStepResponse {
  actionName: string;
  summary: string;
  riskLevel: "low" | "medium" | "high";
  approvalRequired: boolean;
  /** Runtime params — passed back verbatim to approve_preview for execution. */
  params: unknown;
}

export interface PlanResponse {
  summary: string;
  explanation: string;
  approvalRequired: boolean;
  steps: PlanStepResponse[];
  hostName: string;
  deployment: string;
  toolboxCount: number;
  flatpakCount: number;
}

export interface BrainConfigResponse {
  provider: string;  // "anthropic" | "ollama"
  model: string;     // e.g. "claude-opus-4-6" or "mistral:7b"
  fallback: boolean; // true when BrainConfig::from_env() failed and defaults were used
}

export type ShellErrorCode =
  | "daemon_not_running"
  | "daemon_permission_denied"
  | "llm_rate_limit"
  | "llm_http_error"
  | "llm_parse_error"
  | "safety_fence"
  | "intent_empty"
  | "role_insufficient"
  | "stale_approval"
  | "execution_failed_with_rollback"
  | "execution_failed_no_rollback"
  | "unknown";

export interface ShellError {
  code: ShellErrorCode;
  message: string;       // human-readable detail, never a raw Rust error string
  systemChanged: boolean;
}

export type DaemonStatus = "unknown" | "connected" | "unreachable";

export interface SetupStatus {
  configExists: boolean;
  providerConfigured: boolean;
}

export interface HardwareInfo {
  gpuName: string | null;
  vramMb: number | null;
  ramMb: number | null;
}

export interface OllamaStatus {
  reachable: boolean;
  models: string[];
  errorMessage: string | null;
}

export interface StepOutput {
  actionName: string;
  status: string;
  outputLines: string[];
}

export interface ExecutionResult {
  outcome: string;
  stepOutputs: StepOutput[];
}
