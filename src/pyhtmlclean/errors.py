"""Typed exceptions raised by pyhtmlclean."""

from __future__ import annotations


class HtmlCleanError(ValueError):
    """Base error for invalid input, invalid policies, and resource limits."""

    def __init__(self, message: str, code: str = "INVALID_INPUT") -> None:
        super().__init__(message)
        self.code = code


class InvalidPolicyError(HtmlCleanError):
    """Raised when a policy cannot be normalized."""

    def __init__(self, message: str) -> None:
        super().__init__(message, "INVALID_POLICY")


class InputTooLargeError(HtmlCleanError):
    """Raised when input exceeds the configured byte limit."""

    def __init__(self, limit: int) -> None:
        super().__init__(
            "Input exceeds max_input_bytes ({0})".format(limit),
            "INPUT_TOO_LARGE",
        )


class TokenLimitError(HtmlCleanError):
    """Raised when the tokenizer emits more tokens than configured."""

    def __init__(self, limit: int) -> None:
        super().__init__(
            "Input exceeds max_tokens ({0})".format(limit),
            "TOKEN_LIMIT_EXCEEDED",
        )


class DepthLimitError(HtmlCleanError):
    """Raised when output element nesting exceeds the configured depth."""

    def __init__(self, limit: int) -> None:
        super().__init__(
            "Input exceeds max_depth ({0})".format(limit),
            "MAX_DEPTH_EXCEEDED",
        )
