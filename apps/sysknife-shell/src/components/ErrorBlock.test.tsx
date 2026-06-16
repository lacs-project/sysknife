import { render, screen } from "@testing-library/react";
import { ErrorBlock } from "./ErrorBlock";
import type { ShellError } from "../types";

const daemonError: ShellError = {
  code: "daemon_not_running",
  message: "unix:///run/lacs/daemon.sock is not available",
  systemChanged: false,
};

const executionError: ShellError = {
  code: "execution_failed_no_rollback",
  message: "Step 2/3 failed — ConfigureService exited with code 1",
  systemChanged: true,
};

describe("ErrorBlock", () => {
  it("renders the title for daemon_not_running", () => {
    render(<ErrorBlock error={daemonError} />);
    expect(screen.getByText(/Cannot reach the SysKnife daemon/)).toBeInTheDocument();
  });

  it("renders 'Nothing has changed' when systemChanged is false", () => {
    render(<ErrorBlock error={daemonError} />);
    expect(screen.getByText(/Nothing has changed/)).toBeInTheDocument();
  });

  it("renders a warning when systemChanged is true", () => {
    render(<ErrorBlock error={executionError} />);
    expect(screen.getByText(/Some changes cannot be automatically reversed/)).toBeInTheDocument();
  });

  it("renders the error message detail", () => {
    render(<ErrorBlock error={daemonError} />);
    expect(screen.getByText(/unix:\/\/\/run\/lacs\/daemon\.sock/)).toBeInTheDocument();
  });

  it("calls onRetry when Retry button is clicked", async () => {
    const onRetry = vi.fn();
    render(<ErrorBlock error={daemonError} onRetry={onRetry} />);
    screen.getByRole("button", { name: /retry/i }).click();
    expect(onRetry).toHaveBeenCalledOnce();
  });
});
