import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { vi } from "vitest";
import App from "./App";
import * as bridge from "./daemonBridge";
import type { PlanResponse } from "./types";

const mockedRequestApproval = vi.mocked(bridge.requestApproval);

vi.mock("./daemonBridge", () => ({
  requestPlan: vi.fn(),
  requestApproval: vi.fn().mockResolvedValue(undefined),
  cancelJob: vi.fn().mockResolvedValue(undefined),
  getBrainConfig: vi.fn().mockResolvedValue({
    provider: "ollama",
    model: "mistral:7b",
    fallback: false,
  }),
  checkSetupStatus: vi.fn().mockResolvedValue({
    configExists: true,
    providerConfigured: true,
  }),
  subscribeDaemonEvents: vi.fn().mockResolvedValue(() => undefined),
}));

const mockedRequestPlan = vi.mocked(bridge.requestPlan);

const READ_ONLY_PLAN: PlanResponse = {
  summary: "Inspect system state",
  explanation: "Reads the current deployment.",
  approvalRequired: false,
  steps: [
    { actionName: "GetSystemState", summary: "Read state", riskLevel: "low", approvalRequired: false, params: {} },
  ],
  hostName: "silverblue", deployment: "fedora/41", toolboxCount: 1, flatpakCount: 2,
};

// Low-risk plan that still requires explicit approval (approvalRequired: true).
// Used to test the Approve button without needing a checkbox or text input.
const LOW_RISK_APPROVAL_PLAN: PlanResponse = {
  summary: "Check system state",
  explanation: "Reads the current state only.",
  approvalRequired: true,
  steps: [
    { actionName: "GetSystemState", summary: "Read state", riskLevel: "low", approvalRequired: true, params: {} },
  ],
  hostName: "silverblue", deployment: "fedora/41", toolboxCount: 1, flatpakCount: 2,
};

const MUTATING_PLAN: PlanResponse = {
  summary: "Install vim",
  explanation: "Layers vim via rpm-ostree.",
  approvalRequired: true,
  steps: [
    { actionName: "InstallPackages", summary: "Layer vim", riskLevel: "high", approvalRequired: true, params: {} },
  ],
  hostName: "silverblue", deployment: "fedora/41", toolboxCount: 0, flatpakCount: 0,
};

describe("App", () => {
  it("renders the shell and shows Ready status", () => {
    render(<App />);
    expect(screen.getByRole("status")).toHaveTextContent("Ready");
  });

  it("shows 'Review plan' status for read-only plan (no approval required)", async () => {
    mockedRequestPlan.mockResolvedValueOnce(READ_ONLY_PLAN);
    render(<App />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "show state" } });
    fireEvent.click(screen.getByRole("button", { name: /generate plan/i }));
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Ready");
    });
  });

  it("transitions to 'Awaiting your approval' for mutating plans", async () => {
    mockedRequestPlan.mockResolvedValueOnce(MUTATING_PLAN);
    render(<App />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "install vim" } });
    fireEvent.click(screen.getByRole("button", { name: /generate plan/i }));
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Awaiting your approval");
    });
  });

  it("stays on Ready and shows error when requestPlan rejects", async () => {
    mockedRequestPlan.mockRejectedValueOnce({
      code: "llm_http_error",
      message: "HTTP 500",
      systemChanged: false,
    });
    render(<App />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "install vim" } });
    fireEvent.click(screen.getByRole("button", { name: /generate plan/i }));
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Ready");
    });
    expect(screen.getByText("HTTP 500")).toBeInTheDocument();
  });

  it("transitions to Failed when requestApproval rejects (not stuck in Executing)", async () => {
    // Regression test: approval_granted is dispatched before requestApproval()
    // resolves. If requestApproval rejects, policy_errored would be dropped in
    // "executing" mode. The fix dispatches job_completed("failed") instead.
    mockedRequestPlan.mockResolvedValueOnce(LOW_RISK_APPROVAL_PLAN);
    mockedRequestApproval.mockRejectedValueOnce(new Error("IPC connection lost"));

    render(<App />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "check state" } });
    fireEvent.click(screen.getByRole("button", { name: /generate plan/i }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Awaiting your approval");
    });

    fireEvent.click(screen.getByRole("button", { name: /approve/i }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Failed");
    });
  });

  it("logs error details to timeline when requestApproval rejects (#53)", async () => {
    mockedRequestPlan.mockResolvedValueOnce(LOW_RISK_APPROVAL_PLAN);
    mockedRequestApproval.mockRejectedValueOnce(new Error("IPC connection lost"));

    render(<App />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "check state" } });
    fireEvent.click(screen.getByRole("button", { name: /generate plan/i }));

    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Awaiting your approval");
    });

    fireEvent.click(screen.getByRole("button", { name: /approve/i }));

    await waitFor(() => {
      // The error appears in both the execution log and the timeline pane
      const matches = screen.getAllByText(/Approval failed: IPC connection lost/);
      expect(matches.length).toBeGreaterThanOrEqual(1);
    });
  });

  it("shows reconnect banner when daemon status changes to unreachable", async () => {
    // Capture the daemon status callback from subscribeDaemonEvents
    let daemonStatusCb: ((status: "connected" | "unreachable") => void) | undefined;
    vi.mocked(bridge.subscribeDaemonEvents).mockImplementation(
      async (_onTimeline, _onOutcome, onDaemonStatus) => {
        daemonStatusCb = onDaemonStatus;
        return () => undefined;
      },
    );

    render(<App />);

    // Initially no banner
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    // Simulate daemon going down
    await waitFor(() => expect(daemonStatusCb).toBeDefined());
    daemonStatusCb!("unreachable");

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/daemon unreachable/i);
    });

    // Simulate reconnect
    daemonStatusCb!("connected");

    await waitFor(() => {
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });
  });

  it("logs config load failure to timeline (#13)", async () => {
    vi.mocked(bridge.getBrainConfig).mockRejectedValueOnce(new Error("Config not found"));

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Config load failed:.*Config not found/)).toBeInTheDocument();
    });
  });

  it("logs setup check failure to timeline (#13)", async () => {
    vi.mocked(bridge.checkSetupStatus).mockRejectedValueOnce(new Error("Tauri unavailable"));

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/Setup check failed:.*Tauri unavailable/)).toBeInTheDocument();
    });
  });

  it("sets grid data-mode attribute to the current mode", async () => {
    mockedRequestPlan.mockResolvedValueOnce(MUTATING_PLAN);
    render(<App />);
    expect(document.querySelector(".grid")?.getAttribute("data-mode")).toBe("idle");

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "install vim" } });
    fireEvent.click(screen.getByRole("button", { name: /generate plan/i }));

    await waitFor(() => {
      expect(document.querySelector(".grid")?.getAttribute("data-mode")).toBe("awaiting-approval");
    });
  });
});
