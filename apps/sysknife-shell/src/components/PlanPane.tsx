import { useCallback, useState } from "react";
import type { PlanResponse, ShellError } from "../types";
import type { ShellMode } from "../shellState";
import { RiskBadge } from "./RiskBadge";
import { ErrorBlock } from "./ErrorBlock";

function hasParams(params: unknown): boolean {
  if (params === null || params === undefined) return false;
  if (typeof params !== "object") return false;
  return Object.keys(params as Record<string, unknown>).length > 0;
}

interface Props {
  plan: PlanResponse;
  mode: ShellMode;
  onApprove: () => void;
  error: ShellError | null;
}

function aggregateRisk(steps: PlanResponse["steps"]): "low" | "medium" | "high" {
  if (steps.some((s) => s.riskLevel === "high")) return "high";
  if (steps.some((s) => s.riskLevel === "medium")) return "medium";
  return "low";
}

// Returns the first high-risk action name for the confirmation input.
// Design choice: the user types one action name as an awareness check — all
// steps are visible in the plan list and the aggregate risk badge communicates
// overall risk. Requiring one name avoids O(n) typing for multi-step plans
// while preserving meaningful friction for high-risk changes.
function firstHighRiskName(steps: PlanResponse["steps"]): string {
  return steps.find((s) => s.riskLevel === "high")?.actionName ?? "";
}

export function PlanPane({ plan, mode, onApprove, error }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set());
  const [checked, setChecked] = useState(false);
  const [confirmText, setConfirmText] = useState("");

  const toggleStepDetail = useCallback((index: number) => {
    setExpandedSteps((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }, []);

  const risk = aggregateRisk(plan.steps);
  const showGate = mode === "awaiting-approval";
  const highRiskName = firstHighRiskName(plan.steps);
  const SHOW_THRESHOLD = 4;
  const visibleSteps = expanded ? plan.steps : plan.steps.slice(0, SHOW_THRESHOLD - 1);
  const hiddenCount = plan.steps.length - visibleSteps.length;

  const approveEnabled =
    risk === "low" ||
    (risk === "medium" && checked) ||
    (risk === "high" && confirmText === highRiskName);

  return (
    <section className="pane pane-plan">
      <div className="pane-header">
        <h2>Plan</h2>
        <RiskBadge level={risk} />
      </div>

      <p className="plan-summary">{plan.summary}</p>
      <p className="plan-explanation">{plan.explanation}</p>

      {plan.steps.some((s) => s.approvalRequired) && (
        <div className="plan-reboot-banner" role="note">
          ⚠ Reboot may be required after execution
        </div>
      )}

      <ol className="plan-steps">
        {visibleSteps.map((step, i) => (
          <li key={`${i}-${step.actionName}`} className="plan-step-wrapper">
            <button
              type="button"
              className="plan-step"
              onClick={() => toggleStepDetail(i)}
              aria-expanded={expandedSteps.has(i)}
            >
              <span className="plan-step__index">{i + 1}</span>
              <code className="plan-step__name">{step.actionName}</code>
              <span className="plan-step__summary">{step.summary}</span>
              <RiskBadge level={step.riskLevel} />
              {step.approvalRequired && (
                <span className="plan-step__approval-note">approval required</span>
              )}
              <span className="plan-step__chevron" aria-hidden>
                {expandedSteps.has(i) ? "▾" : "▸"}
              </span>
            </button>
            {expandedSteps.has(i) && (
              <div className="plan-step__detail">
                <dl className="plan-step__props">
                  <dt>Risk</dt>
                  <dd>{step.riskLevel}</dd>
                  <dt>Approval</dt>
                  <dd>{step.approvalRequired ? "Required" : "Not required"}</dd>
                </dl>
                {hasParams(step.params) && (
                  <pre className="plan-step__params">
                    <code>{JSON.stringify(step.params, null, 2)}</code>
                  </pre>
                )}
              </div>
            )}
          </li>
        ))}
      </ol>

      {hiddenCount > 0 && (
        <button type="button" className="plan-expand" onClick={() => setExpanded(true)}>
          Show {hiddenCount} more step{hiddenCount > 1 ? "s" : ""} ↓
        </button>
      )}

      <p className="plan-context">
        <code>{plan.hostName} · {plan.deployment} · {plan.toolboxCount} toolbox{plan.toolboxCount !== 1 ? "es" : ""} · {plan.flatpakCount} flatpak{plan.flatpakCount !== 1 ? "s" : ""}</code>
      </p>

      {error && <ErrorBlock error={error} />}

      {showGate && (
        <div className="approval-gate">
          <hr />
          {risk === "low" && (
            <button type="button" onClick={onApprove}>
              Approve
            </button>
          )}
          {risk === "medium" && (
            <>
              <label className="approval-gate__checkbox">
                <input
                  type="checkbox"
                  checked={checked}
                  onChange={(e) => setChecked(e.target.checked)}
                />
                I understand this will modify system state
              </label>
              <button type="button" disabled={!checked} onClick={onApprove}>
                Approve
              </button>
            </>
          )}
          {risk === "high" && (
            <>
              <label className="approval-gate__confirm">
                Type <code>{highRiskName}</code> to confirm:
                <input
                  type="text"
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                />
              </label>
              <button type="button" disabled={!approveEnabled} onClick={onApprove}>
                Approve
              </button>
            </>
          )}
        </div>
      )}
    </section>
  );
}
