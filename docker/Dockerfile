FROM ubuntu:20.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install required system packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    wget \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install PlatformIO
RUN pip3 install platformio

# Pre-install Particle platform for faster builds
RUN pio platform install "particle"

# Create working directories
RUN mkdir -p /workspace/input /workspace/output

# Copy the build script
COPY compile.sh /usr/local/bin/compile.sh
RUN chmod +x /usr/local/bin/compile.sh

# Set the working directory
WORKDIR /workspace

# Default command
ENTRYPOINT ["/usr/local/bin/compile.sh"]