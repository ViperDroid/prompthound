"""Detection rules for insecure AI/LLM integration patterns.

Each rule is a heuristic regex applied per line. The framing is LLM-security:
generic dangerous sinks are flagged because model output must never reach them.
Rules are intentionally readable so users can audit and extend them.
"""

import re

# Map file extension -> language bucket.
EXT_LANG = {
    ".py": "py",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "ts",
    ".tsx": "ts",
}

JS = {"js", "ts"}

RULES = [
    {
        "id": "PH001",
        "severity": "CRITICAL",
        "langs": "*",
        "ignorecase": True,
        "title": "Hardcoded AI provider API key",
        "pattern": r"""(sk-ant-[a-z0-9\-_]{20,})|(sk-[a-z0-9]{32,})|((?:openai|anthropic|groq|mistral|cohere|together|gemini)[_-]?api[_-]?key\s*[:=]\s*['"][^'"\s]{12,}['"])""",
        "why": "An LLM/API key is hardcoded in source. Anyone with repo access (or a leaked commit) can use it.",
        "fix": "Load keys from environment variables or a secrets manager; never commit them. Rotate any exposed key.",
    },
    {
        "id": "PH002",
        "severity": "CRITICAL",
        "langs": {"py"},
        "ignorecase": False,
        "title": "eval()/exec() execution sink",
        "pattern": r"\b(eval|exec)\s*\(",
        "why": "Dynamic code execution. If any LLM output or user input can reach this call, it is remote code execution.",
        "fix": "Avoid eval/exec on dynamic data. Parse structured data with ast.literal_eval or json.loads and validate.",
    },
    {
        "id": "PH003",
        "severity": "HIGH",
        "langs": {"py"},
        "ignorecase": False,
        "title": "Shell command execution sink",
        "pattern": r"(os\.system\s*\(|os\.popen\s*\(|subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True)",
        "why": "Command execution sink. LLM/user-controlled text reaching here enables command injection.",
        "fix": "Never pass model/user output to a shell. Use argument lists (shell=False) and strict allowlists.",
    },
    {
        "id": "PH004",
        "severity": "CRITICAL",
        "langs": JS,
        "ignorecase": False,
        "title": "eval()/new Function() execution sink",
        "pattern": r"\b(eval\s*\(|new\s+Function\s*\()",
        "why": "Dynamic code execution. LLM output or user input reaching here is remote code execution.",
        "fix": "Never eval dynamic strings. Use JSON.parse for data and validate against a schema.",
    },
    {
        "id": "PH005",
        "severity": "HIGH",
        "langs": JS,
        "ignorecase": False,
        "title": "Child process execution sink",
        "pattern": r"(child_process|\bexecSync\s*\(|\.exec\s*\(|\bspawnSync?\s*\()",
        "why": "Shell/process execution. Model/user output reaching here enables command injection.",
        "fix": "Avoid passing untrusted text to exec/spawn. Use fixed commands with argument arrays and validation.",
    },
    {
        "id": "PH006",
        "severity": "HIGH",
        "langs": JS,
        "ignorecase": False,
        "title": "LLM output rendered as HTML (XSS sink)",
        "pattern": r"(dangerouslySetInnerHTML|\.innerHTML\s*=|\bv-html\b|document\.write\s*\()",
        "why": "If model output is rendered here without encoding, the model can emit active HTML/JS -> XSS.",
        "fix": "Render model output as text, or sanitize with a vetted library (e.g. DOMPurify) before inserting as HTML.",
    },
    {
        "id": "PH007",
        "severity": "MEDIUM",
        "langs": {"py"},
        "ignorecase": False,
        "title": "Prompt/query built from web request input",
        "pattern": r"f['\"][^'\"]*\{[^}]*(request\.(args|form|json|values|data|get)|flask\.request)[^}]*\}",
        "why": "Untrusted request data is interpolated directly into a prompt or query string (prompt/SQL injection).",
        "fix": "Keep untrusted input in a separate, clearly-delimited field; validate and never mix it with instructions.",
    },
    {
        "id": "PH008",
        "severity": "HIGH",
        "langs": {"py"},
        "ignorecase": False,
        "title": "SQL query built with f-string",
        "pattern": r"\.execute\s*\(\s*f['\"]",
        "why": "SQL built via f-string is injectable. LLM-generated or user text reaching here is SQL injection.",
        "fix": "Use parameterized queries (execute(sql, params)); never format values into SQL.",
    },
    {
        "id": "PH009",
        "severity": "CRITICAL",
        "langs": {"py"},
        "ignorecase": False,
        "title": "LLM given code/shell execution tools",
        "pattern": r"(PythonREPLTool|PythonAstREPLTool|ShellTool|PALChain|load_tools\s*\([^)]*['\"](?:terminal|shell|python_repl)|allow_dangerous_(?:code|requests|deserialization)\s*=\s*True)",
        "why": "The agent can run arbitrary code/commands. Prompt injection then becomes full RCE.",
        "fix": "Avoid code/shell tools for untrusted input; sandbox strictly and require human approval for actions.",
    },
    {
        "id": "PH010",
        "severity": "HIGH",
        "langs": {"py"},
        "ignorecase": False,
        "title": "TLS verification disabled",
        "pattern": r"verify\s*=\s*False",
        "why": "Disabling TLS verification exposes API keys and model traffic to interception.",
        "fix": "Remove verify=False; fix the certificate chain instead.",
    },
    {
        "id": "PH011",
        "severity": "MEDIUM",
        "langs": JS,
        "ignorecase": False,
        "title": "TLS verification disabled",
        "pattern": r"rejectUnauthorized\s*:\s*false",
        "why": "Disabling TLS verification exposes API keys and model traffic to interception.",
        "fix": "Remove rejectUnauthorized:false; fix the certificate chain instead.",
    },
    {
        "id": "PH012",
        "severity": "HIGH",
        "langs": {"py"},
        "ignorecase": False,
        "title": "Insecure deserialization sink (pickle)",
        "pattern": r"pickle\.loads?\s*\(",
        "why": "pickle executes code on load. Never deserialize model/user-controlled data with pickle.",
        "fix": "Use json for data interchange; if pickle is required, only load trusted, integrity-checked data.",
    },
    {
        "id": "PH013",
        "severity": "MEDIUM",
        "langs": {"py"},
        "ignorecase": False,
        "title": "Unsafe YAML load",
        "pattern": r"yaml\.load\s*\((?![^)]*Safe)",
        "why": "yaml.load without SafeLoader can execute code. Dangerous on model/user-provided YAML.",
        "fix": "Use yaml.safe_load().",
    },
    {
        "id": "PH014",
        "severity": "LOW",
        "langs": {"py"},
        "ignorecase": True,
        "title": "Prompt or secrets written to logs",
        "pattern": r"(print|log(?:ger|ging)?\.\w+)\s*\([^)]*\b(prompt|messages|api_key|system_prompt)\b",
        "why": "Logging full prompts/keys can leak sensitive data and system instructions.",
        "fix": "Redact secrets and avoid logging full prompts in production.",
    },
    {
        "id": "PH015",
        "severity": "MEDIUM",
        "langs": JS,
        "ignorecase": False,
        "title": "Redirect/navigation sink",
        "pattern": r"(res\.redirect\s*\(|location\.(?:href|assign)\s*=|window\.location\s*=)",
        "why": "If a model/user-controlled URL reaches here unchecked, it enables open redirect / phishing pivots.",
        "fix": "Validate redirect targets against an exact allowlist of origins/paths.",
    },
    {
        "id": "PH016",
        "severity": "MEDIUM",
        "langs": {"py"},
        "ignorecase": False,
        "title": "Possible SSRF sink (dynamic request URL)",
        "pattern": r"\b(requests\.(?:get|post|put|delete|head|patch|request)|httpx\.(?:get|post|Client|AsyncClient)|urllib\.request\.urlopen|urlopen)\s*\(\s*(?!['\"])",
        "why": "An outbound request is built from a non-literal URL. If the model/user controls it, this is SSRF.",
        "fix": "Validate and allowlist the destination host/scheme before making the request.",
    },
    {
        "id": "PH017",
        "severity": "HIGH",
        "langs": {"py"},
        "ignorecase": False,
        "title": "Server-side template injection sink",
        "pattern": r"\brender_template_string\s*\(",
        "why": "Jinja2 render_template_string with model/user text enables SSTI, which often leads to RCE.",
        "fix": "Render fixed templates with data passed as context variables; never build templates from input.",
    },
    {
        "id": "PH018",
        "severity": "MEDIUM",
        "langs": {"py"},
        "ignorecase": False,
        "title": "Debug mode enabled",
        "pattern": r"\bdebug\s*=\s*True\b",
        "why": "Debug mode leaks internals and, with Flask/Werkzeug, exposes an interactive console (RCE).",
        "fix": "Disable debug in production; gate it behind an environment variable.",
    },
    {
        "id": "PH019",
        "severity": "CRITICAL",
        "langs": "*",
        "ignorecase": False,
        "title": "Hardcoded cloud credential",
        "pattern": r"(AKIA[0-9A-Z]{16}|aws_secret_access_key\s*[:=]\s*['\"][^'\"]{20,}['\"])",
        "why": "A cloud access credential is hardcoded in source and can be abused if leaked.",
        "fix": "Move credentials to environment variables or a secrets manager and rotate the exposed key.",
    },
    {
        "id": "PH020",
        "severity": "HIGH",
        "langs": JS,
        "ignorecase": False,
        "title": "LLM output rendered as HTML (XSS sink)",
        "pattern": r"(insertAdjacentHTML\s*\(|\.outerHTML\s*=)",
        "why": "If model output is written here without encoding, the model can emit active HTML/JS -> XSS.",
        "fix": "Insert model output as text, or sanitize with a vetted library before writing HTML.",
    },
]


def _compile(rule):
    flags = re.IGNORECASE if rule.get("ignorecase") else 0
    compiled = dict(rule)
    compiled["regex"] = re.compile(rule["pattern"], flags)
    return compiled


COMPILED_RULES = [_compile(r) for r in RULES]
