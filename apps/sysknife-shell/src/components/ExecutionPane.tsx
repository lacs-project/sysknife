import { useEffect, useRef, useState } from "react";
import type { ShellMode, TimelineEntry, TimelineEntryKind } from "../shellState";
import type { PlanResponse, ShellError } from "../types";
import { ErrorBlock } from "./ErrorBlock";

const TIMELINE_KIND_COLORS: Record<TimelineEntryKind, string> = {
  system:  "#9db0ff",
  user:    "#8ca2ff",
  success: "#4ade80",
  warning: "#fb923c",
  error:   "#f87171",
};

interface Props {
  mode: ShellMode;
  plan: PlanResponse | null;
  activeJobId: string | null;
  onCancel: () => void;
  onReset: () => void;
  executionError?: ShellError;
  timeline?: TimelineEntry[];
}

export function ExecutionPane({ mode, plan, activeJobId, onCancel, onReset, executionError, timeline }: Props) {
  const [isCanceling, setIsCanceling] = useState(false);
  const logBottomRef = useRef<HTMLLIElement>(null);

  useEffect(() => {
    if (logBottomRef.current && typeof logBottomRef.current.scrollIntoView === "function") {
      logBottomRef.current.scrollIntoView({ behavior: "smooth", block: "end" });
    }
  }, [timeline]);

  const handleCancel = () => {
    setIsCanceling(true);
    onCancel();
  };

  if (mode === "failed" && executionError) {
    return (
      <section className="pane pane-execution">
        <h2>Execution</h2>
        <ErrorBlock error={executionError} onReset={onReset} />
        <button type="button" onClick={onReset}>New task</button>
      </section>
    );
  }

  if (mode === "needs-reboot" || mode === "rolled-back") {
    return (
      <section className="pane pane-execution">
        <h2>
          {mode === "needs-reboot" ? "Completed" : "Rolled back"}
        </h2>
        {mode === "needs-reboot" && (
          <div className="execution-reboot-banner" role="note">
            <p>⚠ Reboot required to apply changes.</p>
            <p>Run: <code>systemctl reboot</code></p>
          </div>
        )}
        <button type="button" onClick={onReset}>New task</button>
      </section>
    );
  }

  return (
    <section className="pane pane-execution">
      <div className="pane-header">
        <h2>Executing</h2>
        {activeJobId && <code className="execution-job-id">Job: {activeJobId}</code>}
      </div>

      {plan && (
        <ol className="execution-steps">
          {plan.steps.map((step, i) => (
            <li key={`${i}-${step.actionName}`} className="execution-step">
              <span className="execution-step__icon" aria-hidden>○</span>
              <span className="execution-step__index">{i + 1}/{plan.steps.length}</span>
              <code className="execution-step__name">{step.actionName}</code>
              <span className="execution-step__summary">{step.summary}</span>
            </li>
          ))}
        </ol>
      )}

      {timeline && timeline.length > 0 && (
        <div className="execution-log">
          <h3 className="execution-log__title">Live log</h3>
          <ol className="execution-log__entries" aria-live="polite" aria-label="Execution log">
            {timeline.slice(-20).map((entry, i, arr) => (
              <li
                key={entry.id}
                className="execution-log__entry"
                ref={i === arr.length - 1 ? logBottomRef : null}
              >
                <span
                  className="execution-log__dot"
                  style={{ color: TIMELINE_KIND_COLORS[entry.kind] }}
                  aria-hidden
                >
                  ●
                </span>
                <time className="execution-log__timestamp">{entry.timestamp}</time>
                <span className="execution-log__text">{entry.text}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      <div className="execution-actions">
        <button
          type="button"
          onClick={handleCancel}
          disabled={isCanceling}
        >
          {isCanceling ? "Canceling..." : "Cancel"}
        </button>
      </div>
    </section>
  );
}
