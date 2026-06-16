import type { ExecutionResult, PlanResponse, ShellError } from "./types";
import {
  initialShellState,
  shellReducer,
  type ShellState,
} from "./shellState";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const MOCK_PLAN: PlanResponse = {
  summary: "Install vim on this machine",
  explanation: "rpm-ostree will layer vim. A reboot will be required.",
  approvalRequired: true,
  steps: [
    { actionName: "GetSystemState", summary: "Read current deployment", riskLevel: "low", approvalRequired: false, params: {} },
    { actionName: "InstallPackages", summary: "Layer vim via rpm-ostree", riskLevel: "high", approvalRequired: true, params: {} },
  ],
  hostName: "silverblue",
  deployment: "fedora/41",
  toolboxCount: 1,
  flatpakCount: 2,
};

const MOCK_ERROR: ShellError = {
  code: "llm_http_error",
  message: "HTTP 500 — internal server error",
  systemChanged: false,
};

// Helper: drive to awaiting-approval
function reachAwaitingApproval(): ShellState {
  return shellReducer(
    shellReducer(
      shellReducer(initialShellState, { type: "intent_submitted", intent: "install vim" }),
      { type: "plan_ready", plan: MOCK_PLAN },
    ),
    { type: "request_approval" },
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("shellReducer — initial state", () => {
  it("starts in idle mode with daemonStatus unknown", () => {
    expect(initialShellState.mode).toBe("idle");
    expect(initialShellState.daemonStatus).toBe("unknown");
  });
});

describe("shellReducer — happy path", () => {
  it("idle → planning → previewing with full plan", () => {
    const planning = shellReducer(initialShellState, {
      type: "intent_submitted",
      intent: "install vim",
    });
    const previewing = shellReducer(planning, { type: "plan_ready", plan: MOCK_PLAN });

    expect(planning.mode).toBe("planning");
    expect(previewing.mode).toBe("previewing");
    if (previewing.mode === "previewing") {
      expect(previewing.plan.summary).toBe("Install vim on this machine");
      expect(previewing.plan.steps).toHaveLength(2);
    }
  });

  it("previewing → awaiting-approval → executing → succeeded → idle", () => {
    const awaiting = reachAwaitingApproval();
    const executing = shellReducer(awaiting, { type: "approval_granted" });
    const succeeded = shellReducer(executing, { type: "job_completed", outcome: "succeeded" });

    expect(awaiting.mode).toBe("awaiting-approval");
    expect(executing.mode).toBe("executing");
    expect(succeeded.mode).toBe("idle");
    if (succeeded.mode === "idle") {
      expect(succeeded.plan).toBeNull();
    }
  });

  it("executing → needs-reboot", () => {
    const executing = shellReducer(reachAwaitingApproval(), { type: "approval_granted" });
    const needsReboot = shellReducer(executing, { type: "job_completed", outcome: "needs_reboot" });
    expect(needsReboot.mode).toBe("needs-reboot");
  });

  it("executing → rolled-back", () => {
    const executing = shellReducer(reachAwaitingApproval(), { type: "approval_granted" });
    const rolledBack = shellReducer(executing, { type: "job_completed", outcome: "rolled_back" });
    expect(rolledBack.mode).toBe("rolled-back");
    if (rolledBack.mode === "rolled-back") {
      expect(rolledBack.plan).not.toBeNull();
    }
  });

  it("executing → canceled", () => {
    const executing = shellReducer(reachAwaitingApproval(), { type: "approval_granted" });
    const canceled = shellReducer(executing, { type: "job_completed", outcome: "canceled" });
    expect(canceled.mode).toBe("idle");
  });
});

describe("shellReducer — error paths", () => {
  it("plan_errored keeps mode idle and stores error", () => {
    const planning = shellReducer(initialShellState, {
      type: "intent_submitted",
      intent: "install vim",
    });
    const errored = shellReducer(planning, { type: "plan_errored", error: MOCK_ERROR });

    expect(errored.mode).toBe("idle");
    if (errored.mode === "idle") {
      expect(errored.error?.code).toBe("llm_http_error");
    }
  });

  it("intent_submitted clears a previous plan_errored error", () => {
    const withError = shellReducer(
      shellReducer(initialShellState, { type: "intent_submitted", intent: "install vim" }),
      { type: "plan_errored", error: MOCK_ERROR },
    );
    const resubmitted = shellReducer(withError, { type: "intent_submitted", intent: "install neovim" });
    expect(resubmitted.mode).toBe("planning");
    if (resubmitted.mode === "planning") {
      expect(resubmitted.intent).toBe("install neovim");
    }
  });

  it("policy_errored keeps mode previewing and stores planError", () => {
    const previewing = shellReducer(
      shellReducer(initialShellState, { type: "intent_submitted", intent: "install vim" }),
      { type: "plan_ready", plan: MOCK_PLAN },
    );
    const policyErr: ShellError = { code: "role_insufficient", message: "Admin required", systemChanged: false };
    const errored = shellReducer(previewing, { type: "policy_errored", error: policyErr });

    expect(errored.mode).toBe("previewing");
    if (errored.mode === "previewing") {
      expect(errored.planError?.code).toBe("role_insufficient");
    }
  });

  it("job_completed:failed from executing transitions to failed mode", () => {
    const executing = shellReducer(reachAwaitingApproval(), { type: "approval_granted" });
    const failed = shellReducer(executing, { type: "job_completed", outcome: "failed" });

    expect(failed.mode).toBe("failed");
    if (failed.mode === "failed") {
      expect(failed.activeJobId).toBeNull();
      expect(failed.plan).not.toBeNull();
    }
  });
});

describe("shellReducer — daemon status", () => {
  it("daemon_status_changed updates daemonStatus in any mode", () => {
    const updated = shellReducer(initialShellState, {
      type: "daemon_status_changed",
      status: "connected",
    });
    expect(updated.daemonStatus).toBe("connected");
  });
});

describe("shellReducer — timeline entries have timestamp and kind", () => {
  it("intent_submitted appends a user-kind entry with a timestamp", () => {
    const s = shellReducer(initialShellState, { type: "intent_submitted", intent: "install vim" });
    const last = s.timeline[s.timeline.length - 1];
    expect(last.kind).toBe("user");
    expect(last.timestamp).toMatch(/^\d{2}:\d{2}:\d{2}$/);
  });

  it("job_completed:succeeded appends a success-kind entry", () => {
    const executing = shellReducer(reachAwaitingApproval(), { type: "approval_granted" });
    const succeeded = shellReducer(executing, { type: "job_completed", outcome: "succeeded" });
    const last = succeeded.timeline[succeeded.timeline.length - 1];
    expect(last.kind).toBe("success");
  });

  it("plan_errored appends an error-kind entry", () => {
    const planning = shellReducer(initialShellState, { type: "intent_submitted", intent: "x" });
    const errored = shellReducer(planning, { type: "plan_errored", error: MOCK_ERROR });
    const last = errored.timeline[errored.timeline.length - 1];
    expect(last.kind).toBe("error");
  });
});

describe("shellReducer — daemon status", () => {
  it("daemon_status_changed updates daemonStatus", () => {
    const s1 = shellReducer(initialShellState, { type: "daemon_status_changed", status: "connected" });
    expect(s1.daemonStatus).toBe("connected");

    const s2 = shellReducer(s1, { type: "daemon_status_changed", status: "unreachable" });
    expect(s2.daemonStatus).toBe("unreachable");
  });

  it("daemon_status_changed preserves mode and timeline", () => {
    const planning = shellReducer(initialShellState, { type: "intent_submitted", intent: "test" });
    const updated = shellReducer(planning, { type: "daemon_status_changed", status: "unreachable" });
    expect(updated.mode).toBe("planning");
    expect(updated.timeline.length).toBe(planning.timeline.length);
  });
});

describe("shellReducer — reviewing mode", () => {
  const MOCK_EXECUTION_RESULT: ExecutionResult = {
    outcome: "succeeded",
    stepOutputs: [
      { actionName: "GetSystemState", status: "succeeded", outputLines: ["state collected"] },
      { actionName: "InstallPackages", status: "succeeded", outputLines: ["vim layered"] },
    ],
  };

  function reachExecuting(): ShellState {
    return shellReducer(reachAwaitingApproval(), { type: "approval_granted" });
  }

  it("execution_review_ready from executing transitions to reviewing", () => {
    const executing = reachExecuting();
    const reviewing = shellReducer(executing, {
      type: "execution_review_ready",
      executionResult: MOCK_EXECUTION_RESULT,
    });
    expect(reviewing.mode).toBe("reviewing");
    if (reviewing.mode === "reviewing") {
      expect(reviewing.executionResult).toBe(MOCK_EXECUTION_RESULT);
      expect(reviewing.summary).toBeNull();
      expect(reviewing.plan).not.toBeNull();
    }
  });

  it("execution_review_ready from non-executing is ignored", () => {
    const idle = initialShellState;
    const same = shellReducer(idle, {
      type: "execution_review_ready",
      executionResult: MOCK_EXECUTION_RESULT,
    });
    expect(same.mode).toBe("idle");
  });

  it("summary_ready populates summary in reviewing mode", () => {
    const executing = reachExecuting();
    const reviewing = shellReducer(executing, {
      type: "execution_review_ready",
      executionResult: MOCK_EXECUTION_RESULT,
    });
    const withSummary = shellReducer(reviewing, {
      type: "summary_ready",
      summary: "All steps completed successfully.",
    });
    expect(withSummary.mode).toBe("reviewing");
    if (withSummary.mode === "reviewing") {
      expect(withSummary.summary).toBe("All steps completed successfully.");
    }
  });

  it("summary_ready from non-reviewing is ignored", () => {
    const idle = initialShellState;
    const same = shellReducer(idle, { type: "summary_ready", summary: "ignored" });
    expect(same.mode).toBe("idle");
  });

  it("dismiss_review from reviewing transitions to idle", () => {
    const executing = reachExecuting();
    const reviewing = shellReducer(executing, {
      type: "execution_review_ready",
      executionResult: MOCK_EXECUTION_RESULT,
    });
    const idle = shellReducer(reviewing, { type: "dismiss_review" });
    expect(idle.mode).toBe("idle");
    if (idle.mode === "idle") {
      expect(idle.plan).toBeNull();
      expect(idle.intent).toBe("");
    }
  });

  it("dismiss_review from non-reviewing is ignored", () => {
    const executing = reachExecuting();
    const same = shellReducer(executing, { type: "dismiss_review" });
    expect(same.mode).toBe("executing");
  });

  it("reset from reviewing returns to idle", () => {
    const executing = reachExecuting();
    const reviewing = shellReducer(executing, {
      type: "execution_review_ready",
      executionResult: MOCK_EXECUTION_RESULT,
    });
    const afterReset = shellReducer(reviewing, { type: "reset" });
    expect(afterReset.mode).toBe("idle");
    expect(afterReset.intent).toBe("");
  });
});

describe("shellReducer — reset", () => {
  it("reset from failed returns to idle", () => {
    const executing = shellReducer(reachAwaitingApproval(), { type: "approval_granted" });
    const failed = shellReducer(executing, { type: "job_completed", outcome: "failed" });
    const afterReset = shellReducer(failed, { type: "reset" });
    expect(afterReset.mode).toBe("idle");
    expect(afterReset.intent).toBe("");
  });
});
