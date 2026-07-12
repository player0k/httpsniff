#!/bin/bash
set -e

VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
OUTPUT_DIR="./build"
mkdir -p "$OUTPUT_DIR"

echo "Building httpsniff (version: $VERSION)..."

# Windows
echo "→ Windows amd64"
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "$OUTPUT_DIR/httpsniff_windows_amd64.exe" ./cmd/httpsniff

# Linux
echo "→ Linux amd64"
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$OUTPUT_DIR/httpsniff_linux_amd64" ./cmd/httpsniff

# Linux (arm64)
echo "→ Linux arm64"
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "$OUTPUT_DIR/httpsniff_linux_arm64" ./cmd/httpsniff

# macOS Apple Silicon (arm64)
echo "→ macOS arm64"
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o "$OUTPUT_DIR/httpsniff_darwin_arm64" ./cmd/httpsniff

# macOS Intel (amd64)
echo "→ macOS amd64"
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o "$OUTPUT_DIR/httpsniff_darwin_amd64" ./cmd/httpsniff

echo "✅ All builds completed in $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR/"