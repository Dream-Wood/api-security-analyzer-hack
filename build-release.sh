#!/bin/bash
# ====================================================================
# API Security Analyzer - Release Build Script
# ====================================================================
# This script builds production-ready artifacts for GitHub Releases
# ====================================================================

set -e  # Exit on error

echo ""
echo "========================================"
echo "API Security Analyzer - Release Build"
echo "========================================"
echo ""

# Set version (you can pass it as argument or set manually)
RELEASE_VERSION="${1:-1.0.0}"

echo "Building version: $RELEASE_VERSION"
echo ""

# Create release directory
RELEASE_DIR="release-$RELEASE_VERSION"
if [ -d "$RELEASE_DIR" ]; then
    echo "Cleaning old release directory..."
    rm -rf "$RELEASE_DIR"
fi
mkdir -p "$RELEASE_DIR"

echo ""
echo "[1/5] Cleaning previous builds..."
echo "----------------------------------------"
mvn clean

echo ""
echo "[2/5] Running tests..."
echo "----------------------------------------"
mvn test

echo ""
echo "[3/5] Building CLI module..."
echo "----------------------------------------"
mvn package -pl core,report,cli,plugins -am -DskipTests

echo ""
echo "[4/5] Building WebUI module..."
echo "----------------------------------------"
mvn package -pl webui -am -DskipTests

echo ""
echo "[5/5] Collecting artifacts..."
echo "----------------------------------------"

# Copy CLI JAR
cp "cli/target/api-security-analyzer.jar" "$RELEASE_DIR/api-security-analyzer-cli-$RELEASE_VERSION.jar"

# Copy WebUI JAR
cp "webui/target/api-security-analyzer-webui.jar" "$RELEASE_DIR/api-security-analyzer-webui-$RELEASE_VERSION.jar"

# Copy documentation
echo "Copying documentation..."
cp "README.md" "$RELEASE_DIR/README.md"
cp "LICENSE.txt" "$RELEASE_DIR/LICENSE.txt"
[ -f "CHANGELOG.md" ] && cp "CHANGELOG.md" "$RELEASE_DIR/CHANGELOG.md"

# Copy example specs if they exist
if [ -d "test-specs" ]; then
    echo "Copying example specifications..."
    mkdir -p "$RELEASE_DIR/examples"
    cp -r test-specs/* "$RELEASE_DIR/examples/"
fi

# Copy scanner plugins
echo "Copying scanner plugins..."
mkdir -p "$RELEASE_DIR/plugins"
cp plugins/scanner-*.jar "$RELEASE_DIR/plugins/" 2>/dev/null || echo "No plugin JARs found"

# Create usage instructions
echo "Creating USAGE.txt..."
cat > "$RELEASE_DIR/USAGE.txt" << EOF
====================================================================
API Security Analyzer v$RELEASE_VERSION
====================================================================

This package contains:
  - api-security-analyzer-cli-$RELEASE_VERSION.jar  : Command-line tool
  - api-security-analyzer-webui-$RELEASE_VERSION.jar: Web interface
  - plugins/                                         : Scanner plugins (optional)
  - examples/                                        : Sample API specifications
  - README.md                                        : Full documentation
  - LICENSE.txt                                      : License information

====================================================================
REQUIREMENTS
====================================================================
  - Java JDK 21 or higher
  - Windows, Linux, or macOS

====================================================================
QUICK START - CLI
====================================================================

1. Static analysis:
   java -jar api-security-analyzer-cli-$RELEASE_VERSION.jar openapi.yaml

2. Active security testing:
   java -jar api-security-analyzer-cli-$RELEASE_VERSION.jar -m active \\
     -u https://api.example.com \\
     openapi.yaml

3. Full analysis with report:
   java -jar api-security-analyzer-cli-$RELEASE_VERSION.jar -m full \\
     -u https://api.example.com \\
     -f json -o report.json \\
     openapi.yaml

====================================================================
QUICK START - WEB UI
====================================================================

1. Start the web interface:
   java -jar api-security-analyzer-webui-$RELEASE_VERSION.jar

2. Open browser:
   http://localhost:8080

====================================================================
DOCKER
====================================================================

Docker images are available:
  - CLI:   docker pull ghcr.io/your-org/api-security-analyzer:cli
  - WebUI: docker pull ghcr.io/your-org/api-security-analyzer:webui

====================================================================
DOCUMENTATION
====================================================================

Full documentation: https://github.com/your-org/api-security-analyzer
Issues and support: https://github.com/your-org/api-security-analyzer/issues

====================================================================
EOF

# Generate checksums
echo ""
echo "Generating checksums..."
cd "$RELEASE_DIR"
for file in *.jar; do
    sha256sum "$file" > "$file.sha256"
done
cd ..

# Create compressed archives
echo ""
echo "Creating compressed archives..."
tar -czf "$RELEASE_DIR.tar.gz" "$RELEASE_DIR"
zip -r -q "$RELEASE_DIR.zip" "$RELEASE_DIR"

# Create separate plugins archive
echo "Creating plugins archive..."
tar -czf "api-security-analyzer-plugins-$RELEASE_VERSION.tar.gz" -C "$RELEASE_DIR" plugins
[ -x "$(command -v zip)" ] && zip -r -q "api-security-analyzer-plugins-$RELEASE_VERSION.zip" "$RELEASE_DIR/plugins"

echo ""
echo "========================================"
echo "Build completed successfully!"
echo "========================================"
echo ""
echo "Release artifacts are in: $RELEASE_DIR"
echo ""
echo "Archives created:"
echo "  - $RELEASE_DIR.tar.gz"
echo "  - $RELEASE_DIR.zip"
echo ""
echo "Next steps:"
echo "  1. Review the artifacts in $RELEASE_DIR"
echo "  2. Test the JAR files"
echo "  3. Create a git tag: git tag -a v$RELEASE_VERSION -m \"Release v$RELEASE_VERSION\""
echo "  4. Push the tag: git push origin v$RELEASE_VERSION"
echo "  5. Create GitHub Release and upload artifacts"
echo ""
echo "Artifacts:"
ls -lh "$RELEASE_DIR"
echo ""
