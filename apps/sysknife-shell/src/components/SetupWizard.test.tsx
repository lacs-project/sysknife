import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { SetupWizard } from "./SetupWizard";

// Mock the daemonBridge so we don't need a Tauri runtime in tests.
// Each mock call returns a fresh resolved promise.
vi.mock("../daemonBridge", () => ({
  detectHardware: vi.fn(() =>
    Promise.resolve({
      gpuName: "NVIDIA GeForce RTX 4070",
      vramMb: 12282,
      ramMb: 32768,
    }),
  ),
  checkOllamaStatus: vi.fn(() =>
    Promise.resolve({
      reachable: true,
      models: ["qwen3:8b"],
      errorMessage: null,
    }),
  ),
}));

describe("SetupWizard", () => {
  it("renders provider selection by default", () => {
    render(<SetupWizard onDismiss={() => {}} />);
    expect(screen.getByText("Choose your LLM provider")).toBeInTheDocument();
    expect(screen.getByText("Ollama")).toBeInTheDocument();
    expect(screen.getByText("Cloud")).toBeInTheDocument();
  });

  it("selecting Ollama shows model selection", async () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    expect(screen.getByText("Select a model")).toBeInTheDocument();
    expect(screen.getByText("Qwen3-8B")).toBeInTheDocument();
  });

  it("Ollama model step shows hardware info after loading", async () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    await waitFor(() => {
      expect(screen.getByText(/NVIDIA GeForce RTX 4070/)).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByText(/Ollama is running/)).toBeInTheDocument();
    });
  });

  it("Ollama model step shows pulled status for already-pulled models", async () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    await waitFor(() => {
      expect(screen.getByText(/(pulled)/)).toBeInTheDocument();
    });
  });

  it("selecting Ollama then Continue shows config with selected model", async () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    expect(screen.getByRole("heading", { name: /config\.toml/ })).toBeInTheDocument();
    expect(screen.getByText(/provider.*=.*"ollama"/)).toBeInTheDocument();
    expect(screen.getByText(/model.*=.*"qwen3:8b"/)).toBeInTheDocument();
  });

  it("selecting Cloud shows cloud provider sub-selection", () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Cloud"));
    expect(screen.getByText("Choose a cloud provider")).toBeInTheDocument();
    expect(screen.getByText("Anthropic")).toBeInTheDocument();
    expect(screen.getByText("OpenAI")).toBeInTheDocument();
    expect(screen.getByText("Google Gemini")).toBeInTheDocument();
  });

  it("selecting Anthropic shows API key input", () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Cloud"));
    fireEvent.click(screen.getByText("Anthropic"));
    expect(screen.getByPlaceholderText(/sk-ant-/)).toBeInTheDocument();
  });

  it("Anthropic flow generates config with correct provider", () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Cloud"));
    fireEvent.click(screen.getByText("Anthropic"));
    fireEvent.change(screen.getByPlaceholderText(/sk-ant-/), {
      target: { value: "sk-ant-test-key" },
    });
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    expect(screen.getByRole("heading", { name: /config\.toml/ })).toBeInTheDocument();
    expect(screen.getByText(/provider.*=.*"anthropic"/)).toBeInTheDocument();
  });

  it("Done step calls onDismiss", () => {
    const onDismiss = vi.fn();
    render(<SetupWizard onDismiss={onDismiss} />);
    // Go through Ollama flow
    fireEvent.click(screen.getByText("Ollama"));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    // Now on Done step
    fireEvent.click(screen.getByRole("button", { name: /done/i }));
    expect(onDismiss).toHaveBeenCalledOnce();
  });

  it("skip setup link calls onDismiss", () => {
    const onDismiss = vi.fn();
    render(<SetupWizard onDismiss={onDismiss} />);
    fireEvent.click(screen.getByText("Skip setup"));
    expect(onDismiss).toHaveBeenCalledOnce();
  });

  it("shows 'Copy failed' when clipboard write rejects", async () => {
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error("Not allowed")) },
    });

    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));

    const copyBtn = screen.getByRole("button", { name: /copy to clipboard/i });
    fireEvent.click(copyBtn);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /copy failed/i })).toBeInTheDocument();
    });
  });

  it("shows 'Copied' when clipboard write succeeds", async () => {
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
    });

    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));

    const copyBtn = screen.getByRole("button", { name: /copy to clipboard/i });
    fireEvent.click(copyBtn);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /copied/i })).toBeInTheDocument();
    });
  });

  it("Back button from cloud sub-selection returns to category selection", () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Cloud"));
    expect(screen.getByText("Choose a cloud provider")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /back/i }));
    expect(screen.getByText("Choose your LLM provider")).toBeInTheDocument();
  });

  it("Back button from Ollama model step returns to category selection", () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    expect(screen.getByText("Select a model")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /back/i }));
    expect(screen.getByText("Choose your LLM provider")).toBeInTheDocument();
  });

  it("shows 'No GPU detected' when detectHardware returns null", async () => {
    const { detectHardware } = await import("../daemonBridge");
    vi.mocked(detectHardware).mockRejectedValueOnce(new Error("no GPU"));

    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    await waitFor(() => {
      expect(screen.getByText(/No GPU detected/)).toBeInTheDocument();
    });
  });

  it("shows error message when checkOllamaStatus returns unreachable", async () => {
    const { checkOllamaStatus } = await import("../daemonBridge");
    vi.mocked(checkOllamaStatus).mockResolvedValueOnce({
      reachable: false,
      models: [],
      errorMessage: null,
    });

    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    await waitFor(() => {
      expect(screen.getByText(/Ollama is not reachable/)).toBeInTheDocument();
    });
  });

  it("shows custom error message from Ollama status", async () => {
    const { checkOllamaStatus } = await import("../daemonBridge");
    vi.mocked(checkOllamaStatus).mockResolvedValueOnce({
      reachable: false,
      models: [],
      errorMessage: "connection refused on port 11434",
    });

    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    await waitFor(() => {
      expect(screen.getByText(/connection refused on port 11434/)).toBeInTheDocument();
    });
  });

  it("can select a different model in the Ollama step", () => {
    render(<SetupWizard onDismiss={() => {}} />);
    fireEvent.click(screen.getByText("Ollama"));
    // Click on Mistral Small 3.2
    fireEvent.click(screen.getByText("Mistral Small 3.2"));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    // The config block should contain the selected model's tag
    expect(screen.getByText(/model.*=.*"mistral-small3.2:24b"/)).toBeInTheDocument();
  });
});
