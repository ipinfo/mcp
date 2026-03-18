import json
import logging
import sys
from datetime import UTC, datetime
from typing import TextIO, override


class JsonFormatter(logging.Formatter):
    """Format log records as single-line JSON for Google Cloud Logging."""

    @override
    def format(self, record: logging.LogRecord) -> str:
        log: dict[str, str] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info and record.exc_info[0] is not None:
            log["exception"] = self.formatException(record.exc_info)
        return json.dumps(log)


def setup_logging(*, stream: TextIO = sys.stderr) -> None:
    """
    Configure logging to the given stream.

    Uses structured JSON format when writing to stdout,
    plain text when writing to stderr (stdio mode, where stdout is reserved for MCP protocol).
    """
    handler = logging.StreamHandler(stream)

    if stream == sys.stdout:
        handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)

    # Disable uvicorn logger, it's not useful
    logging.getLogger("uvicorn").disabled = True
    logging.getLogger("uvicorn.error").disabled = True
    logging.getLogger("uvicorn.access").disabled = True
