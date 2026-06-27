"""Structured logging to stderr so stdout stays clean for piped report output."""

from __future__ import annotations

import logging
import sys

import structlog


def configure(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
