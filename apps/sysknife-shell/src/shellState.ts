import type { DaemonStatus, ExecutionResult, PlanResponse, ShellError } from "./types";

export type { DaemonStatus, ShellError } from "./types";

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

export type TimelineEntryKind =
  | "system"   // state transitions, daemon events
  | "user"     // explicit user actions
  | "success"  // completions
  | "warning"  // reboot required, rollbacks, cancellations
  | "error";   // failures, policy denials

export interface TimelineEntry {
  id: string;
  timestamp: string;  // HH:MM:SS wall-clock, set in appendTimeline
  kind: TimelineEntryKind;
  text: string;
}

// ---------------------------------------------------------------------------
// Outcome
// ---------------------------------------------------------------------------

export type ShellOutcome =
  | "succeeded"
  | "needs_reboot"
  | "failed"      // execution failure → transitions to "failed" mode
  | "rolled_back"
  | "canceled";

// ---------------------------------------------------------------------------
// State — discriminated union
//
// Invariants:
//   plan is non-null iff mode is previewing/awaiting-approval/executing/needs-reboot/rolled-back/failed
//   activeJobId is non-null only in executing
//   error is non-null only in idle (planning / pre-flight failures)
//   planError is non-null only in previewing / awaiting-approval (policy errors)
// ---------------------------------------------------------------------------

export type ShellMode =
  | "idle"
  | "planning"
  | "previewing"
  | "awaiting-approval"
  | "executing"
  | "reviewing"
  | "needs-reboot"
  | "failed"
  | "rolled-back";

type Base = {
  intent: string;
  timeline: TimelineEntry[];
  daemonStatus: DaemonStatus;
};

type IdleState = Base & {
  mode: "idle";
  plan: null;
  activeJobId: null;
  error: ShellError | null;
};

type PlanningState = Base & {
  mode: "planning";
  plan: null;
  activeJobId: null;
};

type PreviewingState = Base & {
  mode: "previewing";
  plan: PlanResponse;
  activeJobId: null;
  planError: ShellError | null;
};

type ApprovingState = Base & {
  mode: "awaiting-approval";
  plan: PlanResponse;
  activeJobId: null;
  planError: ShellError | null;
};

type ExecutingState = Base & {
  mode: "executing";
  plan: PlanResponse;
  activeJobId: string;
};

type ReviewingState = Base & {
  mode: "reviewing";
  plan: PlanResponse;
  activeJobId: null;
  executionResult: ExecutionResult;
  summary: string | null;
};

type NeedsRebootState = Base & {
  mode: "needs-reboot";
  plan: PlanResponse;
  activeJobId: null;
};

// failed is only reached from execution — plan is always present.
type FailedState = Base & {
  mode: "failed";
  plan: PlanResponse;
  activeJobId: null;
};

// rolled-back is only reached from execution — plan is always present.
type RolledBackState = Base & {
  mode: "rolled-back";
  plan: PlanResponse;
  activeJobId: null;
};

export type ShellState =
  | IdleState
  | PlanningState
  | PreviewingState
  | ApprovingState
  | ExecutingState
  | ReviewingState
  | NeedsRebootState
  | FailedState
  | RolledBackState;

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export type ShellAction =
  | { type: "intent_submitted"; intent: string }
  | { type: "plan_ready"; plan: PlanResponse }
  | { type: "request_approval" }
  | { type: "approval_granted" }
  | { type: "job_completed"; outcome: ShellOutcome }
  | { type: "execution_review_ready"; executionResult: ExecutionResult }
  | { type: "summary_ready"; summary: string }
  | { type: "dismiss_review" }
  | { type: "timeline_event"; text: string; kind: TimelineEntryKind }
  | { type: "plan_errored"; error: ShellError }       // categories 1–2: stays idle
  | { type: "policy_errored"; error: ShellError }     // category 3: stays previewing/approving
  | { type: "cancel_requested" }
  | { type: "daemon_status_changed"; status: DaemonStatus }
  | { type: "reset" };

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

export const initialShellState: ShellState = {
  mode: "idle",
  intent: "",
  plan: null,
  activeJobId: null,
  error: null,
  daemonStatus: "unknown",
  timeline: [],
};

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

export function shellReducer(state: ShellState, action: ShellAction): ShellState {
  switch (action.type) {
    case "intent_submitted": {
      const next: PlanningState = {
        mode: "planning",
        intent: action.intent,
        plan: null,
        activeJobId: null,
        daemonStatus: state.daemonStatus,
        timeline: state.timeline,
      };
      return appendTimeline(next, `Intent submitted: ${action.intent}`, "user");
    }

    case "plan_ready": {
      const next: PreviewingState = {
        mode: "previewing",
        intent: state.intent,
        plan: action.plan,
        activeJobId: null,
        planError: null,
        daemonStatus: state.daemonStatus,
        timeline: state.timeline,
      };
      return appendTimeline(next, `Plan ready: ${action.plan.summary}`, "system");
    }

    case "request_approval": {
      if (state.mode !== "previewing") return state;
      const next: ApprovingState = {
        mode: "awaiting-approval",
        intent: state.intent,
        plan: state.plan,
        activeJobId: null,
        planError: null,
        daemonStatus: state.daemonStatus,
        timeline: state.timeline,
      };
      return appendTimeline(next, "Awaiting user approval", "system");
    }

    case "approval_granted": {
      if (state.mode !== "awaiting-approval") return state;
      const next: ExecutingState = {
        mode: "executing",
        intent: state.intent,
        plan: state.plan,
        activeJobId: "pending",
        daemonStatus: state.daemonStatus,
        timeline: state.timeline,
      };
      return appendTimeline(next, "Approval granted — executing", "user");
    }

    case "job_completed": {
      const { outcome } = action;

      if (outcome === "succeeded") {
        const next: IdleState = {
          mode: "idle",
          intent: state.intent,
          plan: null,
          activeJobId: null,
          error: null,
          daemonStatus: state.daemonStatus,
          timeline: state.timeline,
        };
        return appendTimeline(next, "Job completed successfully", "success");
      }

      if (outcome === "needs_reboot") {
        if (state.mode !== "executing") return state;
        const { plan } = state;
        const next: NeedsRebootState = {
          mode: "needs-reboot",
          intent: state.intent,
          plan,
          activeJobId: null,
          daemonStatus: state.daemonStatus,
          timeline: state.timeline,
        };
        return appendTimeline(next, "Job completed — reboot required", "warning");
      }

      if (outcome === "rolled_back") {
        if (state.mode !== "executing") return state;
        const { plan } = state;
        const next: RolledBackState = {
          mode: "rolled-back",
          intent: state.intent,
          plan,
          activeJobId: null,
          daemonStatus: state.daemonStatus,
          timeline: state.timeline,
        };
        return appendTimeline(next, "Job rolled back", "warning");
      }

      if (outcome === "canceled") {
        const next: IdleState = {
          mode: "idle",
          intent: state.intent,
          plan: null,
          activeJobId: null,
          error: null,
          daemonStatus: state.daemonStatus,
          timeline: state.timeline,
        };
        return appendTimeline(next, "Job canceled", "warning");
      }

      // "failed" — execution failure; plan must be present
      if (state.mode !== "executing") return state;
      const { plan } = state;
      const next: FailedState = {
        mode: "failed",
        intent: state.intent,
        plan,
        activeJobId: null,
        daemonStatus: state.daemonStatus,
        timeline: state.timeline,
      };
      return appendTimeline(next, "Job failed", "error");
    }

    case "execution_review_ready": {
      if (state.mode !== "executing") return state;
      const { plan } = state;
      const next: ReviewingState = {
        mode: "reviewing",
        intent: state.intent,
        plan,
        activeJobId: null,
        executionResult: action.executionResult,
        summary: null,
        daemonStatus: state.daemonStatus,
        timeline: state.timeline,
      };
      return appendTimeline(next, "Execution complete — reviewing results", "success");
    }

    case "summary_ready": {
      if (state.mode !== "reviewing") return state;
      return { ...state, summary: action.summary };
    }

    case "dismiss_review": {
      if (state.mode !== "reviewing") return state;
      const next: IdleState = {
        mode: "idle",
        intent: "",
        plan: null,
        activeJobId: null,
        error: null,
        daemonStatus: state.daemonStatus,
        timeline: state.timeline,
      };
      return next;
    }

    case "plan_errored": {
      // Pre-flight or planning failure — stays idle, error shown inline in IntentPane.
      const next: IdleState = {
        mode: "idle",
        intent: state.intent,
        plan: null,
        activeJobId: null,
        error: action.error,
        daemonStatus: state.daemonStatus,
        timeline: state.timeline,
      };
      return appendTimeline(next, `Planning failed: ${action.error.message}`, "error");
    }

    case "policy_errored": {
      // Policy / stale-approval failure — stays previewing or awaiting-approval.
      if (state.mode !== "previewing" && state.mode !== "awaiting-approval") return state;
      const next = {
        ...state,
        planError: action.error,
      } as PreviewingState | ApprovingState;
      return appendTimeline(next, `Policy error: ${action.error.message}`, "error");
    }

    case "cancel_requested": {
      return appendTimeline(state, "Cancellation requested", "user");
    }

    case "daemon_status_changed": {
      return { ...state, daemonStatus: action.status };
    }

    case "timeline_event": {
      return appendTimeline(state, action.text, action.kind);
    }

    case "reset": {
      return initialShellState;
    }

    default: {
      const exhaustiveCheck: never = action;
      console.warn("[sysknife-shell] shellReducer received unknown action:", exhaustiveCheck);
      return state;
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function appendTimeline<S extends ShellState>(
  state: S,
  text: string,
  kind: TimelineEntryKind,
): S {
  const timestamp = new Date().toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  return {
    ...state,
    timeline: [
      ...state.timeline,
      { id: String(state.timeline.length + 1), timestamp, kind, text },
    ],
  } as S;
}
