@echo off
REM ========================================================
REM Script to install CryptoPro JCSP libraries to Maven
REM ========================================================
REM
REM Prerequisites:
REM 1. Obtain CryptoPro JCSP JAR files (from CryptoPro CSP installation or distribution)
REM 2. Place the JAR files in a directory (e.g., D:\cryptopro-jars\)
REM 3. Update the CRYPTOPRO_JARS_DIR variable below
REM
REM Usage:
REM   install-cryptopro-libs.bat [path-to-jars-directory]
REM
REM Example:
REM   install-cryptopro-libs.bat D:\cryptopro-jars

setlocal enabledelayedexpansion

REM Check if path provided as argument
if "%~1" NEQ "" (
    set "CRYPTOPRO_JARS_DIR=%~1"
) else (
    REM Default path - update this to your JAR files location
    set "CRYPTOPRO_JARS_DIR=D:\cryptopro-jars"
)

echo.
echo ========================================================
echo Installing CryptoPro JCSP Libraries to Maven Repository
echo ========================================================
echo.
echo JAR files location: %CRYPTOPRO_JARS_DIR%
echo.

REM Check if directory exists
if not exist "%CRYPTOPRO_JARS_DIR%" (
    echo ERROR: Directory not found: %CRYPTOPRO_JARS_DIR%
    echo.
    echo Please either:
    echo   1. Place CryptoPro JAR files in: %CRYPTOPRO_JARS_DIR%
    echo   2. Specify the correct path: install-cryptopro-libs.bat C:\path\to\jars
    echo.
    echo Required JAR files:
    echo   - JCP.jar
    echo   - cpSSL.jar
    echo   - JCryptoP.jar
    echo   - JCPRevCheck.jar
    echo   - JCPRevTools.jar
    echo   - asn1rt.jar
    echo   - ASN1P.jar
    echo   - sspiSSL.jar
    echo.
    pause
    exit /b 1
)

set VERSION=2.0.45549

echo Installing CryptoPro libraries...
echo.

REM Install JCP
if exist "%CRYPTOPRO_JARS_DIR%\JCP.jar" (
    echo [1/7] Installing JCP.jar...
    call mvn install:install-file -Dfile="%CRYPTOPRO_JARS_DIR%\JCP.jar" -DgroupId=ru.cryptopro -DartifactId=jcp -Dversion=%VERSION% -Dpackaging=jar
    if errorlevel 1 goto :error
) else (
    echo WARNING: JCP.jar not found - REQUIRED
)

REM Install cpSSL
if exist "%CRYPTOPRO_JARS_DIR%\cpSSL.jar" (
    echo [2/7] Installing cpSSL.jar...
    call mvn install:install-file -Dfile="%CRYPTOPRO_JARS_DIR%\cpSSL.jar" -DgroupId=ru.cryptopro -DartifactId=cpssl -Dversion=%VERSION% -Dpackaging=jar
    if errorlevel 1 goto :error
) else (
    echo WARNING: cpSSL.jar not found - REQUIRED
)

REM Install JCryptoP
if exist "%CRYPTOPRO_JARS_DIR%\JCryptoP.jar" (
    echo [3/7] Installing JCryptoP.jar...
    call mvn install:install-file -Dfile="%CRYPTOPRO_JARS_DIR%\JCryptoP.jar" -DgroupId=ru.cryptopro -DartifactId=jcryptop -Dversion=%VERSION% -Dpackaging=jar
    if errorlevel 1 goto :error
) else (
    echo WARNING: JCryptoP.jar not found - REQUIRED
)

REM Install JCPRevCheck
if exist "%CRYPTOPRO_JARS_DIR%\JCPRevCheck.jar" (
    echo [4/7] Installing JCPRevCheck.jar...
    call mvn install:install-file -Dfile="%CRYPTOPRO_JARS_DIR%\JCPRevCheck.jar" -DgroupId=ru.cryptopro -DartifactId=jcprevcheck -Dversion=%VERSION% -Dpackaging=jar
    if errorlevel 1 goto :error
) else (
    echo WARNING: JCPRevCheck.jar not found - optional
)

REM Install JCPRevTools
if exist "%CRYPTOPRO_JARS_DIR%\JCPRevTools.jar" (
    echo [5/7] Installing JCPRevTools.jar...
    call mvn install:install-file -Dfile="%CRYPTOPRO_JARS_DIR%\JCPRevTools.jar" -DgroupId=ru.cryptopro -DartifactId=jcprevtools -Dversion=%VERSION% -Dpackaging=jar
    if errorlevel 1 goto :error
) else (
    echo WARNING: JCPRevTools.jar not found - optional
)

REM Install asn1rt
if exist "%CRYPTOPRO_JARS_DIR%\asn1rt.jar" (
    echo [6/7] Installing asn1rt.jar...
    call mvn install:install-file -Dfile="%CRYPTOPRO_JARS_DIR%\asn1rt.jar" -DgroupId=ru.cryptopro -DartifactId=asn1rt -Dversion=%VERSION% -Dpackaging=jar
    if errorlevel 1 goto :error
) else (
    echo WARNING: asn1rt.jar not found - REQUIRED
)

REM Install ASN1P
if exist "%CRYPTOPRO_JARS_DIR%\ASN1P.jar" (
    echo [7/7] Installing ASN1P.jar...
    call mvn install:install-file -Dfile="%CRYPTOPRO_JARS_DIR%\ASN1P.jar" -DgroupId=ru.cryptopro -DartifactId=asn1p -Dversion=%VERSION% -Dpackaging=jar
    if errorlevel 1 goto :error
) else (
    echo WARNING: ASN1P.jar not found - REQUIRED
)

REM Install sspiSSL
if exist "%CRYPTOPRO_JARS_DIR%\ASN1P.jar" (
    echo [7/7] Installing ASN1P.jar...
    call mvn install:install-file -Dfile="%CRYPTOPRO_JARS_DIR%\sspiSSL.jar" -DgroupId=ru.cryptopro -DartifactId=sspiSSL -Dversion=%VERSION% -Dpackaging=jar
    if errorlevel 1 goto :error
) else (
    echo WARNING: sspiSSL.jar not found - REQUIRED
)

echo.
echo ========================================================
echo CryptoPro libraries installed successfully!
echo ========================================================
echo.
echo Next step: Rebuild the project with CryptoPro profile
echo.
echo Run: build-with-cryptopro.bat
echo   or: mvn clean package -DskipTests -Pcryptopro-gost -pl cli -am
echo.
goto :end

:error
echo.
echo ERROR: Failed to install CryptoPro libraries
echo Check Maven is installed and in PATH
echo.
pause
exit /b 1

:end
endlocal
