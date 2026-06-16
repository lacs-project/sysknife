import type { ExecutionResult } from "../types";

interface Props {
  executionResult: ExecutionResult;
  summary: string | null;
  onDismiss: () => void;
}

export function ReviewPane({ executionResult, summary, onDismiss }: Props) {
  const outcome = executionResult.outcome;
  const heading =
    outcome === "needs_reboot"
      ? "Execution Complete \u2014 Reboot Required"
      : outcome === "failed"
        ? "Execution Failed"
        : outcome === "rolled_back"
          ? "Execution Rolled Back"
          : "Execution Complete";

  const badgeClass =
    outcome === "succeeded" || outcome === "needs_reboot"
      ? "review-outcome-badge--ok"
      : "review-outcome-badge--fail";

  return (
    <section className="pane pane-review">
      <h2>{heading}</h2>

      <span className={`review-outcome-badge ${badgeClass}`}>{outcome}</span>

      {outcome === "needs_reboot" && (
        <div className="execution-reboot-banner" role="note">
          <p>Reboot required to apply changes.</p>
          <p>Run: <code>systemctl reboot</code></p>
        </div>
      )}

      <ul className="review-steps">
        {executionResult.stepOutputs.map((step, i) => {
          const ok = step.status === "succeeded" || step.status === "needs_reboot";
          return (
            <li key={`${i}-${step.actionName}`} className="review-step">
              <span
                className={`review-step__badge ${ok ? "review-step__badge--ok" : "review-step__badge--fail"}`}
                aria-label={ok ? "succeeded" : "failed"}
              >
                {ok ? "\u2713" : "\u2717"}
              </span>
              <code className="review-step__name">{step.actionName}</code>
              <span className="review-step__status">{step.status}</span>
            </li>
          );
        })}
      </ul>

      <div className="review-summary">
        <h3>Summary</h3>
        {summary === null ? (
          <p className="review-summary__loading">Generating summary...</p>
        ) : (
          <pre className="review-summary__text">{summary}</pre>
        )}
      </div>

      <div className="review-actions">
        <button type="button" onClick={onDismiss}>
          New task
        </button>
      </div>
    </section>
  );
}
