#!/usr/bin/env bash
# Builds every SDK's corpus tool, so the parity test can compare all six.
#
# Skips any runtime that is not installed rather than failing: a machine with
# no JDK should still be able to run the rest, and the parity test says which
# comparisons did not run.
set -uo pipefail
cd "$(dirname "$0")"

status=0

if command -v javac >/dev/null 2>&1; then
  echo "building java"
  javac -d java/build/classes \
    java/src/main/java/io/aegis/security/Aegis.java \
    java/src/test/java/io/aegis/security/AegisTest.java \
    java/tools/CorpusCheck.java || status=1
else
  echo "skipping java: javac not found"
fi

if command -v dotnet >/dev/null 2>&1; then
  echo "building dotnet"
  dotnet build dotnet/tools/CorpusCheck.csproj -v q --nologo >/dev/null || status=1
  dotnet build dotnet/tests/Aegis.Security.Tests.csproj -v q --nologo >/dev/null || status=1
else
  echo "skipping dotnet: dotnet not found"
fi

if command -v go >/dev/null 2>&1; then
  echo "checking go"
  (cd go && go build ./...) || status=1
else
  echo "skipping go: go not found"
fi

# Python and PHP are interpreted; nothing to build.
exit "$status"
