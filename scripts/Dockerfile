FROM debian:12-slim

# Avoid prompts during apt installations
ENV DEBIAN_FRONTEND=noninteractive

# Install Heimdal compiler tooling alongside fundamental C build toolchains
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    heimdal-multidev \
    && rm -rf /var/lib/apt/lists/*

# asn1_compile's generated code depends on <asn1-template.h>, which is an
# internal Heimdal build-tree header NOT shipped by the heimdal-multidev
# -dev package (confirmed: apt-file search finds it in zero Debian/Ubuntu
# packages). The runtime functions it declares are already present in the
# installed libasn1.so, so only the header itself needs vendoring, not an
# implementation. This copy is pinned to the exact git commit the
# installed heimdal-multidev package is built from -- check
# `dpkg -s heimdal-multidev` for the version string (it embeds the commit
# hash, e.g. 7.8.git20221117.28daf24 -> commit 28daf24) and re-fetch from
# https://raw.githubusercontent.com/heimdal/heimdal/<commit>/lib/asn1/asn1-template.h
# if the base image's Heimdal version ever changes.
COPY vendor/asn1-template.h /vendor/asn1-template.h

# Set local tracking execution paths
WORKDIR /workspace

# Copy and configure the automation orchestrator script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set the operational interface
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
