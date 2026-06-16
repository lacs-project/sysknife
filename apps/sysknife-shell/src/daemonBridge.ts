import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { BrainConfigResponse, DaemonStatus, ExecutionResult, HardwareInfo, OllamaStatus, PlanResponse, PlanStepResponse, SetupStatus, ShellError } from "./types";
import type { ShellOutcome, TimelineEntry, TimelineEntryKind } from "./shellState";

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

export async function requestPlan(intent: string): Promise<PlanResponse> {
  requireTauriRuntime();
  return invoke<PlanResponse>("plan_intent", { intent });
}

/** Pass approved steps (with params) to the daemon for execution. */
export async function requestApproval(steps: PlanStepResponse[]): Promise<void> {
  requireTauriRuntime();
  // approve_preview expects { steps: [{ actionName, params }] }
  await invoke("approve_preview", {
    steps: steps.map((s) => ({ actionName: s.actionName, params: s.params })),
  });
}

export async function cancelJob(jobId: string): Promise<void> {
  requireTauriRuntime();
  await invoke("cancel_job", { jobId });
}

export async function getBrainConfig(): Promise<BrainConfigResponse> {
  requireTauriRuntime();
  return invoke<BrainConfigResponse>("get_brain_config");
}

export async function checkSetupStatus(): Promise<SetupStatus> {
  requireTauriRuntime();
  return invoke<SetupStatus>("check_setup_status");
}

export async function detectHardware(): Promise<HardwareInfo> {
  requireTauriRuntime();
  return invoke<HardwareInfo>("detect_hardware");
}

export async function checkOllamaStatus(): Promise<OllamaStatus> {
  requireTauriRuntime();
  return invoke<OllamaStatus>("check_ollama_status");
}

export async function reviewExecution(result: ExecutionResult, intent: string): Promise<string> {
  requireTauriRuntime();
  return invoke<string>("review_execution", { executionResult: result, intent });
}

export async function subscribeDaemonEvents(
  onTimeline: (payload: TimelineEntry) => void,
  onOutcome: (payload: ShellOutcome) => void,
  onDaemonStatus: (status: DaemonStatus) => void,
  onExecutionResult?: (result: ExecutionResult) => void,
): Promise<() => void> {
  requireTauriRuntime();

  const unlisteners: (() => void)[] = [];

  try {
    unlisteners.push(
      await listen<{ id: string; text: string }>("lacs:timeline-entry", (event) => {
        onTimeline({
          id: event.payload.id,
          timestamp: new Date().toLocaleTimeString("en-US", {
            hour12: false,
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          }),
          kind: "system" as TimelineEntryKind,
          text: event.payload.text,
        });
      }),
    );

    unlisteners.push(
      await listen<ShellOutcome>("lacs:job-completed", (event) => {
        onOutcome(event.payload);
      }),
    );

    unlisteners.push(
      await listen<{ status: string }>("lacs:daemon-status", (event) => {
        const status = event.payload.status === "connected" ? "connected" : "unreachable";
        onDaemonStatus(status);
      }),
    );

    if (onExecutionResult) {
      unlisteners.push(
        await listen<ExecutionResult>("lacs:execution-result", (event) => {
          onExecutionResult(event.payload);
        }),
      );
    }
  } catch (err) {
    unlisteners.forEach((fn) => fn());
    throw err;
  }

  return () => unlisteners.forEach((fn) => fn());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function requireTauriRuntime(): void {
  if (!isTauriRuntime()) {
    throw new Error(
      "SysKnife Shell is not running inside a Tauri runtime. The daemon bridge is unavailable.",
    );
  }
}

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI__" in window;
}

// Re-export ShellError for callers that want it from one place
export type { ShellError };
