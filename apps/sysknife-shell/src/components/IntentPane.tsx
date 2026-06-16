import type { FormEvent } from "react";
import type { ShellMode } from "../shellState";
import type { ShellError } from "../types";
import { ErrorBlock } from "./ErrorBlock";

interface Props {
  intent: string;
  mode: ShellMode;
  onSubmit: (intent: string) => void;
  onReset: () => void;
  error: ShellError | null;
}

export function IntentPane({ intent, mode, onSubmit, onReset, error }: Props) {
  const isIdle = mode === "idle";

  if (!isIdle) {
    // Compact read-only strip
    return (
      <section className="pane pane-intent pane-intent--compact">
        <p className="eyebrow">What should SysKnife do?</p>
        <p className="intent-submitted">{intent}</p>
        {mode !== "executing" && (
          <button type="button" onClick={onReset} className="intent-reset">
            Reset
          </button>
        )}
      </section>
    );
  }

  return (
    <section className="pane pane-intent">
      <h2>Intent</h2>
      {error && <ErrorBlock error={error} onRetry={() => {}} />}
      <form
        className="intent-form"
        onSubmit={(event: FormEvent<HTMLFormElement>) => {
          event.preventDefault();
          const formData = new FormData(event.currentTarget);
          onSubmit(String(formData.get("intent") ?? "").trim());
        }}
      >
        <label className="field">
          <span>What should SysKnife do?</span>
          <input
            name="intent"
            defaultValue={intent}
            placeholder="describe a Linux administration task — e.g. 'install vim', 'rebase to Fedora 42'"
          />
        </label>
        <button type="submit">Generate plan</button>
      </form>
    </section>
  );
}
