import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from dotenv import dotenv_values, load_dotenv


OUT_OF_CONTEXT_MESSAGE = "Sorry! This question seems to be out of context!"

# Project root: parent of `src/` (stable regardless of current working directory)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


@dataclass
class ScanContext:
    target: str
    start_port: int
    end_port: int
    open_ports: List[Tuple[int, str]]

    def to_prompt_block(self) -> str:
        ports_text = (
            ", ".join(f"{port} ({service})" for port, service in sorted(self.open_ports))
            if self.open_ports
            else "No open ports detected."
        )
        return (
            f"Target: {self.target}\n"
            f"Port range: {self.start_port}-{self.end_port}\n"
            f"Open ports count: {len(self.open_ports)}\n"
            f"Open ports: {ports_text}"
        )


class AIAssistant:
    def __init__(self):
        self._client = None
        self._api_key = ""
        self._history = []

    def configure(self, api_key: str):
        key = (api_key or "").strip()
        if not key:
            raise ValueError("Gemini API key is required.")
        try:
            from google import genai
        except ImportError as exc:
            raise RuntimeError(
                "Missing dependency: google-genai. Please install requirements first."
            ) from exc

        self._client = genai.Client(api_key=key)
        self._api_key = key

    def configure_from_env(self, env_var: str = "GEMINI_API_KEY") -> bool:
        load_dotenv(dotenv_path=_ENV_FILE)
        raw = dotenv_values(_ENV_FILE).get(env_var, "") or ""
        key = raw.strip()
        if not key:
            self._client = None
            self._api_key = ""
            return False
        self.configure(key)
        return True

    def is_ready(self) -> bool:
        return self._client is not None and bool(self._api_key)

    def clear_history(self):
        self._history = []

    def is_in_scope(self, question: str, context: ScanContext) -> bool:
        q = (question or "").strip().lower()
        if not q:
            return False

        scope_keywords = {
            "port",
            "scan",
            "scanner",
            "network",
            "open",
            "closed",
            "service",
            "target",
            "host",
            "ip",
            "firewall",
            "vulnerability",
            "secure",
            "security",
            "risk",
            "results",
            "result",
            "latency",
            "timeout",
            "ssh",
            "ftp",
            "http",
            "https",
            "dns",
            "rdp",
            "mysql",
        }
        if any(keyword in q for keyword in scope_keywords):
            return True

        mentioned_ports = {int(match) for match in re.findall(r"\b\d{1,5}\b", q)}
        known_ports = {port for port, _ in context.open_ports}
        return bool(mentioned_ports.intersection(known_ports))

    def ask(self, question: str, context: ScanContext) -> str:
        if not self.is_in_scope(question, context):
            return OUT_OF_CONTEXT_MESSAGE
        if not self.is_ready():
            raise RuntimeError("Please provide a valid Gemini API key.")

        system_instruction = (
            "You are an assistant for a Network Port Scanner desktop app. "
            "Only answer questions about scan results, open ports, services, network security "
            "basics, and how to interpret scanner output. "
            "If the question is not related to this app context, return exactly: "
            f"{OUT_OF_CONTEXT_MESSAGE}"
        )
        history_text = "\n".join(self._history[-8:])
        prompt = (
            f"{system_instruction}\n\n"
            "Latest scan context:\n"
            f"{context.to_prompt_block()}\n\n"
            f"Conversation history:\n{history_text}\n\n"
            f"User question:\n{question}"
        )
        try:
            response = self._client.models.generate_content(
                model="gemini-2.5-flash", contents=prompt
            )
            text = (response.text or "").strip()
            if not text:
                text = "I could not generate a response for that request."
        except Exception as exc:
            raise RuntimeError(f"Gemini request failed: {exc}") from exc

        self._history.append(f"User: {question}")
        self._history.append(f"Assistant: {text}")
        return text
