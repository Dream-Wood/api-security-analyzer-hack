@echo off
REM ====================================================================
REM API Security Analyzer - Release Build Script
REM ====================================================================
REM This script builds production-ready artifacts for GitHub Releases
REM ====================================================================

setlocal enabledelayedexpansion

echo.
echo ========================================
echo API Security Analyzer - Release Build
echo ========================================
echo.

REM Set version (you can pass it as argument or set manually)
set RELEASE_VERSION=%1
if "%RELEASE_VERSION%"=="" (
    set RELEASE_VERSION=1.0.0
)

echo Building version: %RELEASE_VERSION%
echo.

REM Create release directory
set RELEASE_DIR=release-%RELEASE_VERSION%
if exist "%RELEASE_DIR%" (
    echo Cleaning old release directory...
    rmdir /s /q "%RELEASE_DIR%"
)
mkdir "%RELEASE_DIR%"

echo.
echo [1/5] Cleaning previous builds...
echo ----------------------------------------
call mvn clean
if errorlevel 1 (
    echo ERROR: Maven clean failed
    exit /b 1
)

echo.
echo [2/5] Running tests...
echo ----------------------------------------
call mvn test
if errorlevel 1 (
    echo ERROR: Tests failed
    exit /b 1
)

echo.
echo [3/5] Building CLI module...
echo ----------------------------------------
call mvn package -pl core,report,cli,plugins -am -DskipTests
if errorlevel 1 (
    echo ERROR: CLI build failed
    exit /b 1
)

echo.
echo [4/5] Building WebUI module...
echo ----------------------------------------
call mvn package -pl webui -am -DskipTests
if errorlevel 1 (
    echo ERROR: WebUI build failed
    exit /b 1
)

echo.
echo [5/5] Collecting artifacts...
echo ----------------------------------------

REM Copy CLI JAR
copy "cli\target\api-security-analyzer.jar" "%RELEASE_DIR%\api-security-analyzer-cli-%RELEASE_VERSION%.jar"
if errorlevel 1 (
    echo ERROR: Failed to copy CLI JAR
    exit /b 1
)

REM Copy WebUI JAR
copy "webui\target\api-security-analyzer-webui.jar" "%RELEASE_DIR%\api-security-analyzer-webui-%RELEASE_VERSION%.jar"
if errorlevel 1 (
    echo ERROR: Failed to copy WebUI JAR
    exit /b 1
)

REM Copy documentation
echo Copying documentation...
copy "README.md" "%RELEASE_DIR%\README.md"
copy "LICENSE.txt" "%RELEASE_DIR%\LICENSE.txt"
if exist "CHANGELOG.md" copy "CHANGELOG.md" "%RELEASE_DIR%\CHANGELOG.md"

REM Copy example specs if they exist
if exist "test-specs" (
    echo Copying example specifications...
    mkdir "%RELEASE_DIR%\examples"
    xcopy /s /q "test-specs\*" "%RELEASE_DIR%\examples\"
)

REM Copy scanner plugins
echo Copying scanner plugins...
mkdir "%RELEASE_DIR%\plugins"
if exist "plugins\scanner-*.jar" (
    copy "plugins\scanner-*.jar" "%RELEASE_DIR%\plugins\" >nul 2>&1
) else (
    echo No plugin JARs found
)

REM Create usage instructions
echo Creating USAGE.txt...
(
    echo ====================================================================
    echo API Security Analyzer v%RELEASE_VERSION%
    echo ====================================================================
    echo.
    echo This package contains:
    echo   - api-security-analyzer-cli-%RELEASE_VERSION%.jar  : Command-line tool
    echo   - api-security-analyzer-webui-%RELEASE_VERSION%.jar: Web interface
    echo   - plugins/                                         : Scanner plugins (optional)
    echo   - examples/                                        : Sample API specifications
    echo   - README.md                                        : Full documentation
    echo   - LICENSE.txt                                      : License information
    echo.
    echo ====================================================================
    echo REQUIREMENTS
    echo ====================================================================
    echo   - Java JDK 21 or higher
    echo   - Windows, Linux, or macOS
    echo.
    echo ====================================================================
    echo QUICK START - CLI
    echo ====================================================================
    echo.
    echo 1. Static analysis:
    echo    java -jar api-security-analyzer-cli-%RELEASE_VERSION%.jar openapi.yaml
    echo.
    echo 2. Active security testing:
    echo    java -jar api-security-analyzer-cli-%RELEASE_VERSION%.jar -m active ^
    echo      -u https://api.example.com ^
    echo      openapi.yaml
    echo.
    echo 3. Full analysis with report:
    echo    java -jar api-security-analyzer-cli-%RELEASE_VERSION%.jar -m full ^
    echo      -u https://api.example.com ^
    echo      -f json -o report.json ^
    echo      openapi.yaml
    echo.
    echo ====================================================================
    echo QUICK START - WEB UI
    echo ====================================================================
    echo.
    echo 1. Start the web interface:
    echo    java -jar api-security-analyzer-webui-%RELEASE_VERSION%.jar
    echo.
    echo 2. Open browser:
    echo    http://localhost:8080
    echo.
    echo ====================================================================
    echo DOCKER
    echo ====================================================================
    echo.
    echo Docker images are available:
    echo   - CLI:   docker pull ghcr.io/your-org/api-security-analyzer:cli
    echo   - WebUI: docker pull ghcr.io/your-org/api-security-analyzer:webui
    echo.
    echo ====================================================================
    echo DOCUMENTATION
    echo ====================================================================
    echo.
    echo Full documentation: https://github.com/your-org/api-security-analyzer
    echo Issues and support: https://github.com/your-org/api-security-analyzer/issues
    echo.
    echo ====================================================================
) > "%RELEASE_DIR%\USAGE.txt"

REM Generate checksums
echo.
echo Generating checksums...
cd "%RELEASE_DIR%"
for %%f in (*.jar) do (
    certutil -hashfile "%%f" SHA256 > "%%f.sha256"
)
cd ..

echo.
echo Creating plugins archive...
tar -czf "api-security-analyzer-plugins-%RELEASE_VERSION%.tar.gz" -C "%RELEASE_DIR%" plugins

echo.
echo ========================================
echo Build completed successfully!
echo ========================================
echo.
echo Release artifacts are in: %RELEASE_DIR%
echo.
echo Next steps:
echo   1. Review the artifacts in %RELEASE_DIR%
echo   2. Test the JAR files
echo   3. Create a git tag: git tag -a v%RELEASE_VERSION% -m "Release v%RELEASE_VERSION%"
echo   4. Push the tag: git push origin v%RELEASE_VERSION%
echo   5. Create GitHub Release and upload artifacts
echo.
echo Artifacts:
dir /b "%RELEASE_DIR%"
echo.

endlocal
