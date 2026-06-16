import { useEffect, useReducer, useCallback, useState, useRef } from "react";
import { IntentPane } from "./components/IntentPane";
import { ExecutionPane } from "./components/ExecutionPane";
import { PlanPane } from "./components/PlanPane";
import { ReviewPane } from "./components/ReviewPane";
import { SetupWizard } from "./components/SetupWizard";
import { TimelinePane } from "./components/TimelinePane";
import {
  checkSetupStatus,
  getBrainConfig,
  requestPlan,
  requestApproval,
  cancelJob,
  reviewExecution,
  subscribeDaemonEvents,
} from "./daemonBridge";
import {
  initialShellState,
  shellReducer,
} from "./shellState";
import type { BrainConfigResponse, ExecutionResult, ShellError } from "./types";

const STATUS_LABELS: Record<string, string> = {
  idle:                "Ready",
  planning:            "Planning...",
  previewing:          "Review plan",
  "awaiting-approval": "Awaiting your approval",
  executing:           "Executing...",
  reviewing:           "Reviewing results",
  "needs-reboot":      "Done — reboot required",
  failed:              "Failed",
  "rolled-back":       "Rolled back",
};

export default function App() {
  const [state, dispatch] = useReducer(shellReducer, initialShellState);
  const [brainConfig, setBrainConfig] = useState<BrainConfigResponse | null>(null);
  const [needsSetup, setNeedsSetup] = useState<boolean | null>(null);
  const pendingExecutionResult = useRef<ExecutionResult | null>(null);
  const intentRef = useRef(state.intent);
  intentRef.current = state.intent;

  // Check setup status on mount
  useEffect(() => {
    checkSetupStatus()
      .then((status) => {
        setNeedsSetup(!status.providerConfigured);
      })
      .catch((err: unknown) => {
        console.warn("[sysknife-shell] checkSetupStatus failed:", err);
        dispatch({ type: "timeline_event", text: `Setup check failed: ${String(err)}`, kind: "warning" });
        // If the check fails (e.g. not running in Tauri), skip the wizard
        setNeedsSetup(false);
      });
  }, []);

  // Load brain config once on mount
  useEffect(() => {
    getBrainConfig()
      .then((cfg) => {
        setBrainConfig(cfg);
        if (cfg.fallback) {
          dispatch({
            type: "timeline_event",
            text: `Brain config fallback: using ${cfg.provider}/${cfg.model}`,
            kind: "warning",
          });
        }
      })
      .catch((err: unknown) => {
        console.warn("[sysknife-shell] getBrainConfig failed:", err);
        dispatch({ type: "timeline_event", text: `Config load failed: ${String(err)}`, kind: "warning" });
      });
  }, []);

  // Subscribe to daemon-pushed timeline and outcome events
  useEffect(() => {
    let unsubscribeFn: (() => void) | null = null;
    let cancelled = false;

    subscribeDaemonEvents(
      (payload) => {
        if (!cancelled) {
          dispatch({ type: "timeline_event", text: payload.text, kind: "system" });
        }
      },
      (outcome) => {
        if (cancelled) return;
        // ALL outcomes that produced an execution result get a review
        const result = pendingExecutionResult.current;
        if (result && (outcome === "succeeded" || outcome === "needs_reboot" || outcome === "failed" || outcome === "rolled_back")) {
          pendingExecutionResult.current = null;
          dispatch({ type: "execution_review_ready", executionResult: result });
          reviewExecution(result, intentRef.current)
            .then((summary) => {
              if (!cancelled && summary) {
                dispatch({ type: "summary_ready", summary });
              }
            })
            .catch((err: unknown) => {
              console.warn("[sysknife-shell] reviewExecution failed:", err);
            });
          return;
        }
        dispatch({ type: "job_completed", outcome });
      },
      (status) => {
        if (!cancelled) {
          dispatch({ type: "daemon_status_changed", status });
        }
      },
      (result) => {
        if (!cancelled) {
          pendingExecutionResult.current = result;
        }
      },
    )
      .then((unsub) => {
        if (cancelled) unsub();
        else unsubscribeFn = unsub;
      })
      .catch((err: unknown) => {
        // Tauri event listener registration failed — log but don't mark the
        // daemon as unreachable; this is a local IPC setup error, not a sign
        // that the daemon process is down.
        console.warn("[sysknife-shell] subscribeDaemonEvents setup failed:", err);
      });

    return () => {
      cancelled = true;
      unsubscribeFn?.();
    };
  }, []);

  const handleIntent = useCallback(async (intent: string) => {
    if (!intent) return;
    dispatch({ type: "intent_submitted", intent });

    try {
      const plan = await requestPlan(intent);
      dispatch({ type: "daemon_status_changed", status: "connected" });
      dispatch({ type: "plan_ready", plan });
      if (plan.approvalRequired) {
        dispatch({ type: "request_approval" });
      } else {
        dispatch({ type: "timeline_event", text: `Read-only plan completed: ${intent}`, kind: "success" });
        dispatch({ type: "job_completed", outcome: "succeeded" });
      }
    } catch (err) {
      dispatch({ type: "daemon_status_changed", status: "unreachable" });
      const shellError: ShellError =
        err && typeof err === "object" && "code" in err
          ? (err as ShellError)
          : { code: "unknown", message: String(err), systemChanged: false };
      dispatch({ type: "plan_errored", error: shellError });
    }
  }, []);

  const handleApprove = useCallback(async () => {
    if (state.mode !== "awaiting-approval") return;
    const steps = state.plan.steps;
    // Dispatch approval_granted immediately so the UI transitions to "executing"
    // and stays responsive during the (potentially long) daemon execution.
    dispatch({ type: "approval_granted" });
    try {
      await requestApproval(steps);
      dispatch({ type: "daemon_status_changed", status: "connected" });
    } catch (err) {
      // The state is now "executing" — policy_errored is only handled in
      // awaiting-approval/previewing mode and would be silently dropped here.
      // Use job_completed("failed") instead so the reducer transitions correctly.
      const message = err instanceof Error ? err.message : String(err);
      dispatch({ type: "timeline_event", text: `Approval failed: ${message}`, kind: "error" });
      dispatch({ type: "daemon_status_changed", status: "unreachable" });
      dispatch({ type: "job_completed", outcome: "failed" });
    }
  }, [state]);

  const handleCancel = useCallback(async () => {
    dispatch({ type: "cancel_requested" });
    if (state.activeJobId) {
      try {
        await cancelJob(state.activeJobId);
      } catch (err: unknown) {
        console.warn("[sysknife-shell] cancelJob failed:", err);
        dispatch({ type: "timeline_event", text: "Cancellation request failed — daemon will resolve the job eventually", kind: "warning" });
      }
    }
  }, [state.activeJobId]);

  const handleReset = useCallback(() => {
    dispatch({ type: "reset" });
  }, []);

  const handleDismissReview = useCallback(() => {
    dispatch({ type: "dismiss_review" });
  }, []);

  // Show the setup wizard when no provider is configured
  if (needsSetup) {
    return (
      <main className="app-shell">
        <header className="app-header">
          <div>
            <p className="eyebrow">SysKnife</p>
            <h1>Linux Agent Control Standard</h1>
          </div>
        </header>
        <SetupWizard onDismiss={() => setNeedsSetup(false)} />
      </main>
    );
  }

  const plan =
    state.mode === "previewing" ||
    state.mode === "awaiting-approval" ||
    state.mode === "executing" ||
    state.mode === "reviewing" ||
    state.mode === "needs-reboot" ||
    state.mode === "rolled-back" ||
    state.mode === "failed"
      ? state.plan
      : null;

  const idleError = state.mode === "idle" ? state.error : null;
  const planError =
    state.mode === "previewing" || state.mode === "awaiting-approval"
      ? state.planError
      : null;

  const daemonLabel =
    state.daemonStatus === "connected" ? "daemon: connected" :
    state.daemonStatus === "unreachable" ? "daemon: unreachable" :
    "daemon: unknown";

  return (
    <main className="app-shell">
      <header className="app-header">
        <div>
          <p className="eyebrow">SysKnife</p>
          <h1>Linux Agent Control Standard</h1>
        </div>
        <div className="app-header__right">
          <div className="status-badge" role="status">
            {STATUS_LABELS[state.mode] ?? state.mode}
          </div>
          {brainConfig && (
            <p className="provider-label">
              {brainConfig.fallback && <span className="provider-label__fallback">⚠ </span>}
              via {brainConfig.provider}/{brainConfig.model}
            </p>
          )}
          <p className={`daemon-indicator daemon-indicator--${state.daemonStatus}`}>
            ● {daemonLabel}
          </p>
          {state.mode !== "executing" && (
            <button type="button" className="reset-btn" onClick={handleReset}>
              Reset
            </button>
          )}
        </div>
      </header>

      {state.daemonStatus === "unreachable" && (
        <div className="reconnect-banner" role="alert">
          <span className="reconnect-banner__icon">!</span>
          <span>
            Daemon unreachable — reconnecting. Actions are unavailable
            until the connection is restored.
          </span>
        </div>
      )}

      <section className="grid" data-mode={state.mode}>
        <IntentPane
          intent={state.intent}
          mode={state.mode}
          onSubmit={handleIntent}
          onReset={handleReset}
          error={idleError}
        />
        {(state.mode === "previewing" || state.mode === "awaiting-approval") && plan && (
          <PlanPane
            plan={plan}
            mode={state.mode}
            onApprove={handleApprove}
            error={planError ?? null}
          />
        )}
        {(state.mode === "executing" ||
          state.mode === "needs-reboot" ||
          state.mode === "rolled-back" ||
          state.mode === "failed") && (
          <ExecutionPane
            mode={state.mode}
            plan={plan}
            activeJobId={state.activeJobId}
            onCancel={handleCancel}
            onReset={handleReset}
            timeline={state.timeline}
          />
        )}
        {state.mode === "reviewing" && (
          <ReviewPane
            executionResult={state.executionResult}
            summary={state.summary}
            onDismiss={handleDismissReview}
          />
        )}
        <TimelinePane entries={state.timeline} />
      </section>
    </main>
  );
}
