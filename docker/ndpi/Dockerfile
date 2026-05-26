# Build ndpiReader from the ntop apt-stable repository (Ubuntu 22.04 base).
#
# Changes vs the old Dockerfile
# ──────────────────────────────
#  • Package renamed: ndpi-tools → libndpi-bin  (ntop repo restructured in 2024)
#  • Added python3 for the pcap_normalize helper
#  • Added pcap_normalize.py: strips the 4-byte BSD/Windows loopback (DLT_NULL)
#    AF header so ndpiReader 4.x can process loopback captures
#  • Added ndpi_entrypoint.sh: wrapper that auto-converts DLT_NULL before ndpiReader
#
# Build
# ─────
#   docker build -t tunnel-testing/ndpi:latest docker/ndpi/
#
# Run (same interface as before — wrapper is transparent)
# ───
#   docker run --rm \
#     -v /path/to/capture.pcap:/capture.pcap:ro \
#     -v /path/to/output:/output \
#     tunnel-testing/ndpi:latest \
#     -i /capture.pcap -J -q -w /output/ndpi_result.json

FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

# ── system dependencies ───────────────────────────────────────────────────────
# lsb-release + whiptail are required by the apt-ntop-stable meta-package.
# python3 is used by pcap_normalize.py (no extra pip packages needed).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        libpcap0.8 \
        lsb-release \
        python3 \
        whiptail \
    && rm -rf /var/lib/apt/lists/*

# ── ntop repository ───────────────────────────────────────────────────────────
RUN curl -fsSL https://packages.ntop.org/apt-stable/22.04/all/apt-ntop-stable.deb \
        -o /tmp/apt-ntop.deb \
    && dpkg -i /tmp/apt-ntop.deb \
    && rm /tmp/apt-ntop.deb \
    && apt-get update

# ── ndpiReader ────────────────────────────────────────────────────────────────
# The binary is now in libndpi-bin (was called ndpi-tools in older releases).
RUN apt-get install -y --no-install-recommends \
        libndpi-bin \
    && rm -rf /var/lib/apt/lists/*

# ── DLT_NULL normalisation helper ────────────────────────────────────────────
COPY pcap_normalize.py /usr/local/bin/pcap_normalize.py
COPY ndpi_entrypoint.sh /usr/local/bin/ndpi_entrypoint.sh
RUN chmod +x /usr/local/bin/pcap_normalize.py \
             /usr/local/bin/ndpi_entrypoint.sh

ENTRYPOINT ["/usr/local/bin/ndpi_entrypoint.sh"]
CMD ["--help"]
