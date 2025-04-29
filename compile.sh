#!/usr/bin/env bash
set -e

# 1) Build your provider as usual
mvn clean package -DskipTests

# 2) Unpack it into a temp directory
TMP=./target/tmp-unpack
rm -rf "$TMP"
mkdir -p "$TMP"
(cd "$TMP" && jar xf ../keycloak-header-authenticator-1.0.0.jar)

# 3) Remove any leftover metadata
rm -rf "$TMP"/META-INF/maven

# 4) Re-zip everything *without* directory entries (-D) and with no compression level (-0)
(cd "$TMP" && zip -r -0 -D ../keycloak-header-authenticator-stripped.jar .)
