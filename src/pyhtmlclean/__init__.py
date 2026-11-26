"""pyhtmlclean: zero-dependency allowlist HTML sanitization."""

from .entities import decode_entities, escape_attribute, escape_text
from .errors import (
    DepthLimitError,
    HtmlCleanError,
    InputTooLargeError,
    InvalidPolicyError,
    TokenLimitError,
)
from .policy import (
    BASIC_ELEMENTS,
    POLICY_BASIC,
    POLICY_PROSE,
    POLICY_STRICT,
    POLICY_STRIP_ALL,
    PROSE_ELEMENTS,
    STRICT_ELEMENTS,
    Policy,
)
from .sanitizer import (
    DROP_CONTENT_ELEMENTS,
    Sanitizer,
    inspect_html,
    sanitize,
    sanitize_srcset,
    sanitize_style,
    sanitize_url,
    strip_html,
)
from .tokenizer import Token, Tokenizer, tokenize

__version__ = "1.0.0"

__all__ = [
    "BASIC_ELEMENTS",
    "DROP_CONTENT_ELEMENTS",
    "DepthLimitError",
    "HtmlCleanError",
    "InputTooLargeError",
    "InvalidPolicyError",
    "POLICY_BASIC",
    "POLICY_PROSE",
    "POLICY_STRICT",
    "POLICY_STRIP_ALL",
    "PROSE_ELEMENTS",
    "Policy",
    "STRICT_ELEMENTS",
    "Sanitizer",
    "Token",
    "Tokenizer",
    "TokenLimitError",
    "decode_entities",
    "escape_attribute",
    "escape_text",
    "inspect_html",
    "sanitize",
    "sanitize_srcset",
    "sanitize_style",
    "sanitize_url",
    "strip_html",
    "tokenize",
]
