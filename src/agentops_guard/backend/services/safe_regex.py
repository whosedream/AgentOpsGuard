from __future__ import annotations

from typing import Any

import re2


MAX_CONFIGURABLE_PATTERN_CHARACTERS = 4_096
MAX_CONFIGURABLE_PATTERN_MEMORY_BYTES = 8 * 1024 * 1024


class SafeRegexError(ValueError):
    pass


def compile_configurable_pattern(pattern: str) -> Any:
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= MAX_CONFIGURABLE_PATTERN_CHARACTERS:
        raise SafeRegexError("configurable scanner pattern length is invalid")
    options = re2.Options()
    options.case_sensitive = False
    options.dot_nl = True
    options.log_errors = False
    options.max_mem = MAX_CONFIGURABLE_PATTERN_MEMORY_BYTES
    options.never_capture = True
    try:
        return re2.compile(pattern, options=options)
    except re2.error as exc:
        raise SafeRegexError("configurable scanner pattern is not supported by RE2") from exc
