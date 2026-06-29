#!/bin/bash
#
# Particle Cloud Compiler Script
#
# This script compiles a Particle firmware sketch using PlatformIO.
# It takes an input directory containing the sketch and libraries,
# and outputs a .bin file and build log to the output directory.
#
# Usage: compile.sh <input_dir> <output_dir> [platform]
#
# Arguments:
#   input_dir  - Directory containing the sketch (must contain platformio.ini and src/)
#   output_dir - Directory where output files will be written
#   platform   - Target platform (photon, core, etc.) - optional, defaults to photon
#
# Outputs:
#   output_dir/firmware.bin  - Compiled firmware binary
#   output_dir/build.log     - Build log
#

set -e

# Parse arguments
INPUT_DIR="${1:-/workspace/input}"
OUTPUT_DIR="${2:-/workspace/output}"
PLATFORM="${3:-photon}"

# Validate input directory
if [ ! -d "$INPUT_DIR" ]; then
    echo "ERROR: Input directory does not exist: $INPUT_DIR"
    exit 1
fi

# Validate platformio.ini exists
if [ ! -f "$INPUT_DIR/platformio.ini" ]; then
    echo "ERROR: platformio.ini not found in input directory"
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Copy input to workspace
rm -rf /workspace/build
cp -r "$INPUT_DIR" /workspace/build
cd /workspace/build

# Initialize PlatformIO project if needed
if [ ! -d ".pio" ]; then
    pio init --board "$PLATFORM" 2>&1 | tee -a "$OUTPUT_DIR/build.log"
fi

# Run the build
echo "Starting build for platform: $PLATFORM"
echo "Input directory: $INPUT_DIR"
echo "Output directory: $OUTPUT_DIR"
echo "========================================"

# Build the firmware
pio run 2>&1 | tee "$OUTPUT_DIR/build.log"

# Check if build was successful
if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo "Build successful!"
    
    # Find and copy the .bin file
    BIN_FILE=$(find .pio/build -name "firmware.bin" 2>/dev/null | head -1)
    if [ -n "$BIN_FILE" ]; then
        cp "$BIN_FILE" "$OUTPUT_DIR/firmware.bin"
        echo "Firmware binary copied to $OUTPUT_DIR/firmware.bin"
    else
        echo "WARNING: firmware.bin not found in build output"
        echo "WARNING: firmware.bin not found in build output" >> "$OUTPUT_DIR/build.log"
    fi
    
    exit 0
else
    echo "Build failed. Check build.log for details."
    exit 1
fi