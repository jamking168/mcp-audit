# Glama builds and starts this image to verify the server answers introspection.
# The entry point is stdlib-only (mcp_server_stdlib.py), so the image needs no
# Python packages at all — that removes the "externally managed environment"
# failure hit when installing into the system interpreter.
FROM python:3.12-slim

# git is only used when a tool call scans a remote repository URL.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY mcp_audit.py mcp_server_stdlib.py mcp_server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# stdio transport: JSON-RPC over stdin/stdout.
CMD ["python3", "mcp_server_stdlib.py"]
