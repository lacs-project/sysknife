import type { ShellError, ShellErrorCode } from "../types";

interface Props {
  error: ShellError;
  onRetry?: () => void;
  onReset?: () => void;
}

const TITLES: Record<ShellErrorCode, string> = {
  daemon_not_running:              "Cannot reach the SysKnife daemon",
  daemon_permission_denied:        "Permission denied on daemon socket",
  llm_rate_limit:                  "Could not generate a plan (rate limit)",
  llm_http_error:                  "Could not generate a plan",
  llm_parse_error:                 "Could not parse the plan",
  safety_fence:                    "Action blocked by safety policy",
  intent_empty:                    "Intent is empty",
  role_insufficient:               "Insufficient permissions",
  stale_approval:                  "Approval expired",
  execution_failed_with_rollback:  "Execution failed",
  execution_failed_no_rollback:    "Execution failed",
  unknown:                         "An unexpected error occurred",
};

export function ErrorBlock({ error, onRetry, onReset }: Props) {
  const title = TITLES[error.code] ?? TITLES.unknown;
  const showRetry = onRetry && !error.systemChanged;
  const showReset = onReset;

  return (
    <div className="error-block" role="alert">
      <div className="error-block__header">
        <span className="error-block__icon" aria-hidden>⛔</span>
        <strong className="error-block__title">{title}</strong>
      </div>

      <p className="error-block__message">{error.message}</p>

      {error.systemChanged ? (
        <p className="error-block__state error-block__state--warning">
          ⚠ Some changes cannot be automatically reversed. Review the timeline and restore manually if needed.
        </p>
      ) : (
        <p className="error-block__state">Nothing has changed.</p>
      )}

      <div className="error-block__actions">
        {showRetry && (
          <button type="button" onClick={onRetry}>
            Retry
          </button>
        )}
        {showReset && (
          <button type="button" onClick={onReset}>
            New task
          </button>
        )}
      </div>
    </div>
  );
}
