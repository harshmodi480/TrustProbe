FROM python:3.11-slim

# Install Docker CLI and Node.js (needed for npm-sourced MCP servers in static mode)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg lsb-release nodejs npm \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
       | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
       https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer cache)
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir "fastapi>=0.110" "uvicorn[standard]>=0.29" "sse-starlette>=1.8"

# Copy source
COPY . .

# Install trustprobe itself + uv (provides uvx for PyPI-sourced MCP servers)
RUN pip install --no-cache-dir -e . uv

# Install demo server requirements so local-path scans work inside the container
RUN find /app/demo_servers -name "requirements.txt" \
    -exec pip install --no-cache-dir -r {} \; 2>/dev/null || true

# Ensure output dirs exist
RUN mkdir -p /app/out /app/ui_configs

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/ || exit 1

CMD ["uvicorn", "web_app:app", "--host", "0.0.0.0", "--port", "8000"]
