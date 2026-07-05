FROM debian:12-slim

# Avoid prompts during apt installations
ENV DEBIAN_FRONTEND=noninteractive

# Install Heimdal compiler tooling alongside fundamental C build toolchains
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    heimdal-multidev \
    && rm -rf /var/lib/apt/lists/*

# Set local tracking execution paths
WORKDIR /workspace

# Copy and configure the automation orchestrator script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set the operational interface
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
