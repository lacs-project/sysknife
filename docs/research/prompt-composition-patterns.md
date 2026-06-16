# Prompt-composition patterns survey (2026-04-25)

Research goal: identify concrete design patterns for context-conditional prompt
construction, evaluated against the SysKnife per-distro problem: detect OS first,
then build only the prompt relevant to that OS — no Ubuntu content for Fedora
hosts, no Fedora content for Ubuntu hosts.

The `build_system_prompt(user_prefs, distro_hint)` signature in
`crates/sysknife-brain/src/prompt.rs` already accepts a `distro_hint`; the
question is how to dispatch on it cleanly instead of appending conditional
string fragments.

---

## 1. Dynamic System Prompt Middleware — LangChain (JS v3+)

- **Mechanism:** `dynamicSystemPromptMiddleware` wraps an agent with a closure
  that receives `(state, runtime.context)` at call time and returns the full
  system prompt string. The context is typed via a Zod schema declared on the
  agent. The closure is the only place conditional logic lives — the rendered
  prompt never contains dead branches. A parallel API for Python is
  `createReactAgent({ prompt: (state) => ... })` where the `prompt` field
  accepts a function rather than a string.

  ```typescript
  const agent = createAgent({
    middleware: [
      dynamicSystemPromptMiddleware<Context>((state, runtime) => {
        if (runtime.context.userRole === "admin")
          return ADMIN_PROMPT;
        return VIEWER_PROMPT;
      })
    ],
    contextSchema  // Zod schema — typed, validated at agent boundary
  });
  ```

  The context (OS, role, env) is passed in the `config` object at call time,
  separate from the conversation messages. The dispatch function is ordinary
  code — no DSL, no template engine, no special framework magic.

- **Source:** <https://docs.langchain.com/oss/javascript/langchain/context-engineering>
- **Fits SysKnife per-distro problem?** Yes — this is structurally identical to
  `build_system_prompt(distro_hint)` already in prompt.rs; the middleware pattern
  just formalizes it as a typed closure over a context struct rather than a free
  function with string mutation.

---

## 2. RunnableBranch / add_conditional_edges — LangGraph

- **Mechanism:** LangGraph's `add_conditional_edges` routes graph execution to
  different nodes based on a routing function over graph state. Each node can
  carry its own prompt. This is a **graph-level** dispatch, not a string-level
  one: Fedora and Ubuntu would be separate graph nodes with separate `Runnable`
  chains, each containing a fully self-contained prompt. The routing function
  inspects `state["distro"]` and returns the node name.

  ```python
  def route_by_distro(state) -> Literal["fedora_planner", "ubuntu_planner"]:
      return "fedora_planner" if state["distro"] == "fedora" else "ubuntu_planner"

  graph.add_conditional_edges("detect_os", route_by_distro)
  ```

  `RunnableBranch` is the LCEL-layer equivalent for non-graph chains: a list of
  `(predicate, runnable)` tuples; the first matching predicate wins.

- **Source:** <https://docs.langchain.com/langsmith/troubleshooting-studio>
- **Fits SysKnife per-distro problem?** Yes, and it's the best structural match
  when distro-specific prompts diverge significantly (different action sets,
  different tool lists). For SysKnife, where `sysknife-brain` is a single Rust
  function rather than a Python graph, the equivalent is a `match distro_hint`
  at the top of `build_system_prompt` that selects among fully-rendered static
  strings rather than fragmenting a single string.

---

## 3. Signature-scoped Module Dispatch — DSPy

- **Mechanism:** A DSPy `Signature` is a typed declaration of
  `input_fields -> output_fields` plus a docstring that becomes the task
  description. Conditional context lives at the **module** level, not the
  prompt level: you define separate `dspy.Module` subclasses (e.g.
  `FedoraPlanner(dspy.Module)`, `UbuntuPlanner(dspy.Module)`) each wrapping a
  `ChainOfThought` or `Predict` with a different `Signature`. A dispatch
  function (plain Python code) instantiates the right module based on the
  detected OS. The optimizer (`dspy.MIPROv2`) then compiles each module's
  prompt independently from labeled examples — the human never writes the
  distro-specific few-shot blocks by hand.

  The key architectural point: the per-context branching is **code**, not
  template logic. Prompt construction is delegated to the optimizer, not to
  string concatenation.

- **Source:** <https://dspy.ai/learn/programming/signatures>
- **Fits SysKnife per-distro problem?** Partial — the module dispatch model is
  the right shape, but DSPy's optimizer requires labeled training data per
  module. SysKnife's E2E stories could serve as that data, but only if the
  project is willing to adopt the Python DSPy runtime. As a design principle
  (separate module classes per distro, dispatch in calling code) it translates
  to Rust cleanly; the optimization toolchain does not.

---

## 4. YAML-declared Template + Handlebars Conditionals — Semantic Kernel

- **Mechanism:** `PromptTemplateConfig` loads a YAML file that declares the
  template body (Handlebars or Jinja2 syntax), input variable names and types,
  and per-service execution settings. Handlebars supports `{{#if condition}}`
  blocks directly in the template body, enabling conditional section inclusion
  without custom rendering code. Template files can be one-per-variant (loaded
  by name) or one unified template with `{{#if distro == "ubuntu"}}` guards.

  Named variant loading is done at the caller:
  ```python
  config = PromptTemplateConfig.from_yaml(f"prompts/{distro}.yaml")
  ```

  This externalizes prompt text from code — versions, reviews, and A/B tests
  become file diffs rather than code diffs.

- **Source:** <https://learn.microsoft.com/en-us/semantic-kernel/concepts/prompts/yaml-schema>
- **Fits SysKnife per-distro problem?** Partial — file-per-distro YAML is clean
  for teams doing prompt versioning and A/B testing via file system. For
  SysKnife (Rust, compile-time `include_str!` for prompts, no Python runtime),
  the YAML loading machinery doesn't apply. The underlying idea — one file per
  distro, selected by name — translates directly to Rust modules or `const`
  blocks selected at construction time.

---

## 5. XML-tagged Section Inclusion — Anthropic Guidance

- **Mechanism:** Anthropic's prompt engineering guidance (current as of 2026)
  does not provide a conditional inclusion API; it provides a structural
  convention. The recommendation is to use XML tags to demarcate sections
  (`<os_context>`, `<distro_tools>`, `<examples>`) so the model can parse
  prompt regions clearly. The guidance implicitly endorses **separate system
  prompt variants per use-case** over one monolithic prompt with dead
  conditional branches: "think of Claude as a new employee who lacks context
  on your norms — the more precisely you explain what you want, the better."

  For Claude Opus 4.7 specifically, the guidance emphasizes that the model
  follows instructions literally and does not generalize across sections
  silently. This means a Fedora-specific section that is present but tagged
  "ignore for Ubuntu" is a liability — the model may read it anyway. The
  correct approach is to exclude it from the rendered prompt entirely.

  Anthropic provides no template framework. The pattern they implicitly
  recommend is: build the string you want at call time; don't embed control
  flow inside the prompt text.

- **Source:** <https://platform.claude.com/docs/en/build-with-claude/prompt-engineering/claude-prompting-best-practices>
- **Fits SysKnife per-distro problem?** Yes — Anthropic's guidance directly
  supports the "build only what's relevant" goal. Use XML tags to section the
  rendered prompt (`<distro_tools>`, `<examples>`) rather than conditional
  prose. Do not embed "if Ubuntu, then..." inside the string; select the
  right string before the API call.

---

## 6. Compiled Grammar Dispatch — Microsoft `guidance`

- **Mechanism:** `guidance` (guidance-ai/guidance on GitHub) is a Python library
  that interleaves generation and control flow by compiling templates into
  token-level logit constraints. Its `select()` primitive constrains the model
  to generate one of a fixed set of options. Branching is expressed as
  grammar alternatives, not as if/else over a string. The model's token
  generation is literally constrained to the valid paths — no dead text is ever
  rendered or seen by the model.

  ```python
  lm += select(["fedora_plan", "ubuntu_plan", "arch_plan"], name="distro_branch")
  ```

  Unlike classical strategy dispatch, branching is generative: the model
  chooses the branch, not the calling code. This is powerful for output
  format selection but is the wrong shape for system-prompt selection, where
  the distro is already known before the API call.

- **Source:** <https://github.com/guidance-ai/guidance>
- **Fits SysKnife per-distro problem?** No — `guidance` solves the problem of
  constraining model output, not the problem of constructing the right input
  prompt. The distro is a hard fact known before planning starts; using `select`
  to let the model choose its own OS context is backwards. Rust has no `guidance`
  equivalent and none is needed here.

---

## 7. Single-template Context Injection — Honeycomb Query Assistant (Production)

- **Mechanism:** Honeycomb's production system uses one master prompt template
  with sequential context injection: fixed syntax rules, domain knowledge, then
  the per-customer schema blob, then few-shot examples. There is no per-customer
  or per-query-type branching — just one template, filled in. The only
  conditional logic is temporal schema filtering (drop fields not seen in the
  last 7 days) to manage token budget. Zero-shot chain-of-thought variants were
  tested globally and abandoned because they produced null plans on vague inputs.

  The notable engineering decision: simplicity won over sophistication.
  Branched prompt strategies were considered but not implemented, because
  the single-template approach was easier to debug and evaluate.

- **Source:** <https://www.honeycomb.io/blog/hard-stuff-nobody-talks-about-llm>
- **Fits SysKnife per-distro problem?** No — Honeycomb's problem is per-customer
  data injection into a fixed task (NL→query). SysKnife's problem is that
  different distros have fundamentally different action sets (rpm-ostree vs.
  apt, flatpak vs. snap). A single template with injected action lists is still
  viable, but the token waste and confusion risk are real: an Ubuntu model
  seeing rpm-ostree tool names it cannot use is worse than it not seeing them
  at all.

---

## Synthesis

The dominant production pattern across frameworks is **closure/function dispatch
over a typed context struct** — not template conditionals, not configuration DSLs.
The calling code detects the context (OS, role, env), constructs the typed struct,
and passes it to a function that returns the fully-rendered system prompt for that
context. No dead branches are ever serialized into the prompt string.

For SysKnife specifically, `build_system_prompt(user_prefs, distro_hint)` is
already the right interface. The refactoring needed is inside the function body:
replace string fragment appending with a `match distro_hint { Some(Fedora) =>
FEDORA_PROMPT, Some(Ubuntu) => UBUNTU_PROMPT, None => GENERIC_PROMPT }` where
each arm returns a fully-formed static string. Shared invariants (role
declaration, `propose_plan` mandate, trust-boundary rules, worked examples) live
in named `const` blocks that are concatenated into each variant — this is the
Rust-idiomatic version of the Semantic Kernel "YAML per variant with shared
partials" pattern. The result is zero dead text in the rendered prompt, a
trivially testable dispatch function, and prompt variants that can be diffed,
reviewed, and E2E-tested independently.
