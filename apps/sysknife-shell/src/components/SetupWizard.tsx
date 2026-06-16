import { useEffect, useState } from "react";
import type { HardwareInfo, OllamaStatus } from "../types";

type WizardStep = "select" | "ollama-model" | "cloud-key" | "configure" | "done";
type ProviderCategory = "local" | "cloud";
type CloudProvider =
  | "anthropic"
  | "openai"
  | "gemini"
  | "groq"
  | "deepseek"
  | "mistral"
  | "xai";

interface Props {
  onDismiss: () => void;
}

const CONFIG_PATH = "~/.config/lacs/config.toml";

// ---------------------------------------------------------------------------
// Model catalogue — VRAM requirements are approximate Q4 quantised sizes
// ---------------------------------------------------------------------------

interface ModelOption {
  id: string;
  label: string;
  ollamaTag: string;
  vramMb: number;
  description: string;
  recommended?: boolean;
  /**
   * Whether Ollama accepts the `think` field for this model. Keep in
   * sync with `THINKING_MODEL_PREFIXES` in
   * `crates/lacs-brain/src/planner.rs`. Currently: qwen3 family, qwq,
   * deepseek-r1.
   */
  supportsThinking?: boolean;
}

const OLLAMA_MODELS: ModelOption[] = [
  {
    id: "qwen3-8b",
    label: "Qwen3-8B",
    ollamaTag: "qwen3:8b",
    vramMb: 5_000,
    description: "Best tool-calling reliability",
    recommended: true,
    supportsThinking: true,
  },
  {
    id: "gemma4-e4b",
    label: "Gemma 4 E4B",
    ollamaTag: "gemma4:4b-it-qat",
    vramMb: 5_000,
    description: "Google's latest, native function calling",
  },
  {
    id: "gemma4-e2b",
    label: "Gemma 4 E2B",
    ollamaTag: "gemma4:2b",
    vramMb: 2_000,
    description: "Ultra-light, for 4GB GPUs",
  },
  {
    id: "qwen3-30b-a3b",
    label: "Qwen3-30B-A3B",
    ollamaTag: "qwen3:30b-a3b",
    vramMb: 17_000,
    description: "Premium quality, needs 24GB+ GPU",
    supportsThinking: true,
  },
  {
    id: "gemma4-27b",
    label: "Gemma 4 27B",
    ollamaTag: "gemma4:27b",
    vramMb: 18_000,
    description: "MoE, near-31B quality",
  },
  {
    id: "mistral-small-3.2",
    label: "Mistral Small 3.2",
    ollamaTag: "mistral-small3.2:24b",
    vramMb: 15_000,
    description: "Battle-tested function calling",
  },
];

const CLOUD_PROVIDERS: { id: CloudProvider; label: string; placeholder: string; envVar: string }[] = [
  { id: "anthropic", label: "Anthropic", placeholder: "sk-ant-...", envVar: "ANTHROPIC_API_KEY" },
  { id: "openai", label: "OpenAI", placeholder: "sk-...", envVar: "OPENAI_API_KEY" },
  { id: "gemini", label: "Google Gemini", placeholder: "AI...", envVar: "GEMINI_API_KEY" },
  { id: "groq", label: "Groq", placeholder: "gsk_...", envVar: "GROQ_API_KEY" },
  { id: "deepseek", label: "DeepSeek", placeholder: "sk-...", envVar: "DEEPSEEK_API_KEY" },
  { id: "mistral", label: "Mistral", placeholder: "...", envVar: "MISTRAL_API_KEY" },
  { id: "xai", label: "xAI", placeholder: "xai-...", envVar: "XAI_API_KEY" },
];

const DEFAULT_CLOUD_MODELS: Record<CloudProvider, string> = {
  anthropic: "claude-sonnet-4-20250514",
  openai: "gpt-4.1",
  gemini: "gemini-2.0-flash",
  groq: "llama-3.3-70b-versatile",
  deepseek: "deepseek-chat",
  mistral: "mistral-large-latest",
  xai: "grok-3",
};

// ---------------------------------------------------------------------------
// Config generators
// ---------------------------------------------------------------------------

function ollamaConfig(ollamaTag: string, thinkOverride: boolean | null): string {
  // `thinkOverride === null` means "use lacs-brain's auto-detection" —
  // we emit no `ollama_think` line in that case so the default path
  // is exercised and visible in `lacs-test-cli --doctor` output.
  const base = `[llm]\nprovider = "ollama"\nmodel    = "${ollamaTag}"`;
  if (thinkOverride === null) return base;
  return `${base}\nollama_think = ${thinkOverride}`;
}

function cloudConfig(provider: CloudProvider): string {
  const model = DEFAULT_CLOUD_MODELS[provider];
  return `[llm]\nprovider = "${provider}"\nmodel    = "${model}"`;
}

// ---------------------------------------------------------------------------
// Helpers to load hardware/Ollama info — stubbed when not in Tauri
// ---------------------------------------------------------------------------

import { detectHardware, checkOllamaStatus } from "../daemonBridge";

async function safeDetectHardware(): Promise<HardwareInfo | null> {
  try {
    return await detectHardware();
  } catch (e) {
    console.warn("[lacs-shell] detectHardware failed:", e);
    return null;
  }
}

async function safeCheckOllama(): Promise<OllamaStatus | null> {
  try {
    return await checkOllamaStatus();
  } catch (e) {
    console.warn("[lacs-shell] checkOllamaStatus failed:", e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SetupWizard({ onDismiss }: Props) {
  const [step, setStep] = useState<WizardStep>("select");
  const [category, setCategory] = useState<ProviderCategory | null>(null);
  const [cloudProvider, setCloudProvider] = useState<CloudProvider | null>(null);
  const [selectedModel, setSelectedModel] = useState<ModelOption>(OLLAMA_MODELS[0]);
  const [apiKey, setApiKey] = useState("");
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  // Thinking-mode override. `null` = defer to lacs-brain's auto-detection.
  // Only exposed in the UI when the selected model supports thinking.
  const [thinkOverride, setThinkOverride] = useState<boolean | null>(null);

  // Hardware & Ollama state (loaded when entering Ollama step)
  const [hardware, setHardware] = useState<HardwareInfo | null>(null);
  const [ollamaStatus, setOllamaStatus] = useState<OllamaStatus | null>(null);
  const [hwLoading, setHwLoading] = useState(false);

  // Load hardware info when entering the Ollama model step
  useEffect(() => {
    if (step !== "ollama-model") return;
    let cancelled = false;
    setHwLoading(true);

    Promise.all([safeDetectHardware(), safeCheckOllama()]).then(([hw, ollama]) => {
      if (cancelled) return;
      setHardware(hw);
      setOllamaStatus(ollama);
      setHwLoading(false);
    });

    return () => { cancelled = true; };
  }, [step]);

  const handleSelectCategory = (cat: ProviderCategory) => {
    setCategory(cat);
    if (cat === "local") {
      setStep("ollama-model");
    }
    // Cloud stays on select to pick a sub-provider
  };

  const handleSelectCloudProvider = (p: CloudProvider) => {
    setCloudProvider(p);
    setStep("cloud-key");
  };

  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopyFailed(true);
      setTimeout(() => setCopyFailed(false), 2000);
    }
  };

  const fitsVram = (model: ModelOption): boolean => {
    if (!hardware?.vramMb) return true; // unknown = don't gray out
    return model.vramMb <= hardware.vramMb;
  };

  const modelAlreadyPulled = (model: ModelOption): boolean => {
    if (!ollamaStatus?.models) return false;
    // Ollama tags may include ":latest" suffix
    return ollamaStatus.models.some(
      (m) => m === model.ollamaTag || m === `${model.ollamaTag}:latest`,
    );
  };

  // Derive config content based on current selections. Only pass a
  // think override for models that actually support thinking — for
  // non-thinking models it would be written but silently ignored, which
  // just clutters config.toml.
  const configContent =
    category === "local"
      ? ollamaConfig(
          selectedModel.ollamaTag,
          selectedModel.supportsThinking ? thinkOverride : null,
        )
      : cloudProvider
        ? cloudConfig(cloudProvider)
        : "";

  const currentCloudMeta = cloudProvider
    ? CLOUD_PROVIDERS.find((p) => p.id === cloudProvider)
    : null;

  // ---- Step: Provider category selection ----
  if (step === "select" && !category) {
    return (
      <section className="pane setup-wizard">
        <h2>Choose your LLM provider</h2>
        <p className="setup-wizard__subtitle">
          SysKnife needs an LLM to generate administration plans. Pick one to get started.
        </p>
        <div className="setup-wizard__cards">
          <button
            type="button"
            className="setup-wizard__card"
            onClick={() => handleSelectCategory("local")}
          >
            <span className="setup-wizard__card-title">Ollama</span>
            <span className="setup-wizard__card-tag">recommended</span>
            <p className="setup-wizard__card-desc">
              Runs on your hardware, no API key needed. Best for privacy.
            </p>
          </button>
          <button
            type="button"
            className="setup-wizard__card"
            onClick={() => handleSelectCategory("cloud")}
          >
            <span className="setup-wizard__card-title">Cloud</span>
            <span className="setup-wizard__card-tag">api key required</span>
            <p className="setup-wizard__card-desc">
              Higher quality models via Anthropic, OpenAI, Google, and more.
            </p>
          </button>
        </div>
        <button type="button" className="setup-wizard__skip" onClick={onDismiss}>
          Skip setup
        </button>
      </section>
    );
  }

  // ---- Step: Cloud provider sub-selection ----
  if (step === "select" && category === "cloud") {
    return (
      <section className="pane setup-wizard">
        <h2>Choose a cloud provider</h2>
        <p className="setup-wizard__subtitle">
          Select the provider you have an API key for.
        </p>
        <div className="setup-wizard__cards">
          {CLOUD_PROVIDERS.map((p) => (
            <button
              key={p.id}
              type="button"
              className="setup-wizard__card"
              onClick={() => handleSelectCloudProvider(p.id)}
            >
              <span className="setup-wizard__card-title">{p.label}</span>
            </button>
          ))}
        </div>
        <div className="setup-wizard__actions">
          <button
            type="button"
            className="intent-reset"
            onClick={() => { setCategory(null); }}
          >
            Back
          </button>
        </div>
        <button type="button" className="setup-wizard__skip" onClick={onDismiss}>
          Skip setup
        </button>
      </section>
    );
  }

  // ---- Step: Ollama model selection with hardware detection ----
  if (step === "ollama-model") {
    return (
      <section className="pane setup-wizard">
        <h2>Select a model</h2>

        {/* Hardware summary */}
        {hwLoading && (
          <p className="setup-wizard__subtitle">Detecting hardware...</p>
        )}
        {!hwLoading && hardware && (
          <p className="setup-wizard__hw-summary">
            {hardware.gpuName
              ? `GPU: ${hardware.gpuName}${hardware.vramMb ? ` (${Math.round(hardware.vramMb / 1024)}GB VRAM)` : ""}`
              : "No GPU detected"}
            {" | "}RAM: {hardware.ramMb != null ? `${Math.round(hardware.ramMb / 1024)}GB` : "unknown"}
          </p>
        )}
        {!hwLoading && !hardware && (
          <p className="setup-wizard__hw-summary">No GPU detected</p>
        )}

        {/* Ollama reachability */}
        {!hwLoading && ollamaStatus && (
          <p className={`setup-wizard__ollama-status ${ollamaStatus.reachable ? "setup-wizard__ollama-status--ok" : "setup-wizard__ollama-status--err"}`}>
            {ollamaStatus.reachable
              ? "Ollama is running"
              : ollamaStatus.errorMessage
                ? `Ollama is not reachable: ${ollamaStatus.errorMessage}`
                : "Ollama is not reachable -- make sure it is installed and running"}
          </p>
        )}

        {/* Model list */}
        <div className="setup-wizard__models" role="radiogroup" aria-label="Model selection">
          {OLLAMA_MODELS.map((m) => {
            const fits = fitsVram(m);
            const pulled = modelAlreadyPulled(m);
            return (
              <button
                key={m.id}
                type="button"
                role="radio"
                aria-checked={selectedModel.id === m.id}
                className={[
                  "setup-wizard__model",
                  selectedModel.id === m.id ? "setup-wizard__model--selected" : "",
                  fits ? "setup-wizard__model--fits" : "setup-wizard__model--heavy",
                ].join(" ")}
                onClick={() => setSelectedModel(m)}
              >
                <span className="setup-wizard__model-name">
                  {m.recommended && <span className="setup-wizard__model-rec" aria-label="recommended">*</span>}
                  {m.label}
                  {pulled && <span className="setup-wizard__model-pulled"> (pulled)</span>}
                </span>
                <span className="setup-wizard__model-vram">
                  {m.vramMb >= 1024 ? `${Math.round(m.vramMb / 1024)}GB VRAM` : `${m.vramMb}MB VRAM`}
                </span>
                <span className="setup-wizard__model-desc">{m.description}</span>
                {!fits && hardware?.vramMb && (
                  <span className="setup-wizard__model-warn">
                    requires {Math.round(m.vramMb / 1024)}GB VRAM
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {hardware?.vramMb != null && selectedModel && !fitsVram(selectedModel) && (
          <p className="setup-wizard__warning">
            This model requires more VRAM than detected. It may run slowly using CPU offloading.
          </p>
        )}

        {selectedModel.supportsThinking && (
          <fieldset className="setup-wizard__thinking">
            <legend>Thinking mode</legend>
            <p className="setup-wizard__subtitle">
              {selectedModel.label} can emit a hidden reasoning trace before
              answering, which improves tool-calling reliability. The trace
              counts against the generation budget and can take minutes on
              CPU-only hosts.
            </p>
            <div className="setup-wizard__thinking-choices" role="radiogroup" aria-label="Thinking mode">
              <label>
                <input
                  type="radio"
                  name="think"
                  checked={thinkOverride === null}
                  onChange={() => setThinkOverride(null)}
                />
                Auto (recommended) — let SysKnife decide from the model name
              </label>
              <label>
                <input
                  type="radio"
                  name="think"
                  checked={thinkOverride === true}
                  onChange={() => setThinkOverride(true)}
                />
                Force on — GPU hosts only
              </label>
              <label>
                <input
                  type="radio"
                  name="think"
                  checked={thinkOverride === false}
                  onChange={() => setThinkOverride(false)}
                />
                Force off — CPU hosts or when you hit Ollama timeouts
              </label>
            </div>
          </fieldset>
        )}

        <div className="setup-wizard__actions">
          <button
            type="button"
            className="intent-reset"
            onClick={() => { setCategory(null); setStep("select"); }}
          >
            Back
          </button>
          <button type="button" onClick={() => setStep("configure")}>
            Continue
          </button>
        </div>
        <button type="button" className="setup-wizard__skip" onClick={onDismiss}>
          Skip setup
        </button>
      </section>
    );
  }

  // ---- Step: Cloud API key input ----
  if (step === "cloud-key" && currentCloudMeta) {
    return (
      <section className="pane setup-wizard">
        <h2>{currentCloudMeta.label} API key</h2>
        <p className="setup-wizard__subtitle">
          Enter your {currentCloudMeta.label} API key.
        </p>
        <div className="setup-wizard__field">
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder={currentCloudMeta.placeholder}
          />
        </div>
        <p className="setup-wizard__note">
          The key will NOT be stored in config.toml. Set it as{" "}
          <code>{currentCloudMeta.envVar}</code> in your environment instead.
        </p>
        <div className="setup-wizard__actions">
          <button
            type="button"
            className="intent-reset"
            onClick={() => { setCloudProvider(null); setStep("select"); }}
          >
            Back
          </button>
          <button type="button" onClick={() => setStep("configure")}>
            Continue
          </button>
        </div>
        <button type="button" className="setup-wizard__skip" onClick={onDismiss}>
          Skip setup
        </button>
      </section>
    );
  }

  // ---- Step: Config preview ----
  if (step === "configure") {
    const isOllama = category === "local";
    return (
      <section className="pane setup-wizard">
        <h2>Create config.toml</h2>
        <p className="setup-wizard__subtitle">
          Create the file <code>{CONFIG_PATH}</code> with this content:
        </p>
        <pre className="setup-wizard__config">
          <code>{configContent}</code>
        </pre>
        <div className="setup-wizard__actions">
          <button
            type="button"
            className="intent-reset"
            onClick={() => handleCopy(configContent)}
          >
            {copyFailed ? "Copy failed" : copied ? "Copied" : "Copy to clipboard"}
          </button>
          <button type="button" onClick={() => setStep("done")}>
            Continue
          </button>
        </div>
        {isOllama && (
          <div className="setup-wizard__hint">
            <p>Make sure Ollama is installed and running, then pull the model:</p>
            <pre className="setup-wizard__config">
              <code>ollama pull {selectedModel.ollamaTag}</code>
            </pre>
          </div>
        )}
        {!isOllama && currentCloudMeta && (
          <div className="setup-wizard__hint">
            <p>
              Set the API key in your shell profile or systemd environment:
            </p>
            <pre className="setup-wizard__config">
              <code>export {currentCloudMeta.envVar}="{apiKey || `your-${currentCloudMeta.id}-key`}"</code>
            </pre>
          </div>
        )}
        <button type="button" className="setup-wizard__skip" onClick={onDismiss}>
          Skip setup
        </button>
      </section>
    );
  }

  // ---- Step: Done ----
  return (
    <section className="pane setup-wizard">
      <h2>Setup complete</h2>
      <p className="setup-wizard__subtitle">
        Restart the shell to apply the new configuration. SysKnife will read{" "}
        <code>{CONFIG_PATH}</code> on startup and use{" "}
        {category === "local" ? "Ollama" : currentCloudMeta?.label ?? "your provider"} as the LLM provider.
      </p>
      <div className="setup-wizard__actions">
        <button type="button" onClick={onDismiss}>
          Done
        </button>
      </div>
    </section>
  );
}
