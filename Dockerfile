# Glama builds and starts this image to verify the server responds to
# introspection requests. The scanner itself is stdlib-only; the only
# dependency here is the official MCP Python SDK used by mcp_server.py.
FROM python:3.12-slim

# git is needed only when a tool call scans a remote repository URL.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-mcp.txt ./
RUN pip install --no-cache-dir -r requirements-mcp.txt

COPY mcp_audit.py mcp_server.py ./

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# stdio transport: the MCP client speaks JSON-RPC over stdin/stdout.
CMD ["python3", "mcp_server.py"]
