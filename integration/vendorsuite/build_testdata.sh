#!/bin/bash
# build_testdata.sh — Builds the vendor-suite-3.2.zip test fixture.
#
# This script creates all artifacts described in SCAN_APPROACH.md §4.1 and
# assembles them into vendor-suite-3.2.zip. The result is a minimal but
# structurally complete delivery that exercises every supported format.
#
# Requirements: 7zz, rpmbuild, dpkg-deb, gcab, wixl (from msitools)
# All installable via: brew install sevenzip rpm dpkg gcab msitools
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTDATA="$SCRIPT_DIR/testdata"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "=== Building vendor-suite-3.2.zip test fixture ==="
echo "Work dir: $WORK"

# ─── Helper: create a minimal JAR with pom.properties ───
make_jar() {
  local jar_name="$1"
  local group_id="$2"
  local artifact_id="$3"
  local version="$4"
  local jar_dir="$WORK/jar-$artifact_id"
  mkdir -p "$jar_dir/META-INF/maven/$group_id/$artifact_id"

  cat > "$jar_dir/META-INF/MANIFEST.MF" <<MANIFEST
Manifest-Version: 1.0
Created-By: build_testdata.sh
Implementation-Title: $artifact_id
Implementation-Version: $version
MANIFEST

  cat > "$jar_dir/META-INF/maven/$group_id/$artifact_id/pom.properties" <<POM
groupId=$group_id
artifactId=$artifact_id
version=$version
POM

  # Add a minimal .class placeholder
  echo "placeholder" > "$jar_dir/Dummy.class"

  (cd "$jar_dir" && zip -qr "$WORK/$jar_name" .)
  echo "  Created $jar_name"
}

# ─── 1. JARs ───
echo "--- Building JARs ---"
make_jar "catalina.jar" "org.apache.tomcat" "tomcat-catalina" "9.0.98"
make_jar "tomcat-embed-core-9.0.98.jar" "org.apache.tomcat.embed" "tomcat-embed-core" "9.0.98"
make_jar "servlet-api.jar" "javax.servlet" "javax.servlet-api" "4.0.1"

# ─── 2. EAR ───
echo "--- Building EAR ---"
ear_dir="$WORK/ear-build"
mkdir -p "$ear_dir/META-INF"
cat > "$ear_dir/META-INF/MANIFEST.MF" <<MANIFEST
Manifest-Version: 1.0
Created-By: build_testdata.sh
Application-Name: vendor-app
MANIFEST
cat > "$ear_dir/META-INF/application.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<application xmlns="http://java.sun.com/xml/ns/javaee" version="6">
  <display-name>vendor-app</display-name>
</application>
XML
echo "placeholder" > "$ear_dir/stub.war"
(cd "$ear_dir" && zip -qr "$WORK/vendor-app.ear" .)
echo "  Created vendor-app.ear"

# ─── 3. apache-tomcat-9.0.98.tar.gz ───
echo "--- Building apache-tomcat-9.0.98.tar.gz ---"
tomcat_dir="$WORK/tomcat-build"
mkdir -p "$tomcat_dir/lib" "$tomcat_dir/webapps"
cp "$WORK/catalina.jar" "$tomcat_dir/lib/"
cp "$WORK/tomcat-embed-core-9.0.98.jar" "$tomcat_dir/lib/"
cp "$WORK/servlet-api.jar" "$tomcat_dir/lib/"
cp "$WORK/vendor-app.ear" "$tomcat_dir/webapps/"
tar czf "$WORK/apache-tomcat-9.0.98.tar.gz" -C "$WORK/tomcat-build" .
echo "  Created apache-tomcat-9.0.98.tar.gz"

# ─── 4. resources.tgz ───
echo "--- Building resources.tgz ---"
res_dir="$WORK/resources-build/translations"
mkdir -p "$res_dir"
echo "greeting=Hallo Welt" > "$res_dir/de.properties"
echo "greeting=Hello World" > "$res_dir/en.properties"
tar czf "$WORK/resources.tgz" -C "$WORK/resources-build" .
echo "  Created resources.tgz"

# ─── 5. server-3.2.rpm ───
echo "--- Building server-3.2.rpm ---"
rpm_build="$WORK/rpmbuild"
mkdir -p "$rpm_build"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cat > "$rpm_build/SPECS/server.spec" <<'SPEC'
Name:    server
Version: 3.2
Release: 1
Summary: Minimal test server package
License: MIT
Group:   Development/Tools

%description
Minimal RPM for integration testing.

%install
mkdir -p %{buildroot}/opt/server
echo "server binary placeholder" > %{buildroot}/opt/server/server

%files
/opt/server/server
SPEC
rpmbuild --define "_topdir $rpm_build" -bb "$rpm_build/SPECS/server.spec" --quiet 2>/dev/null
# Find the built RPM (architecture varies by platform)
RPM_FILE=$(find "$rpm_build/RPMS" -name '*.rpm' -type f | head -1)
if [ -z "$RPM_FILE" ]; then
  echo "ERROR: RPM build failed" >&2
  exit 1
fi
cp "$RPM_FILE" "$WORK/server-3.2.rpm"
echo "  Created server-3.2.rpm"

# ─── 6. libssl1.1_1.1.1n-0_amd64.deb ───
echo "--- Building libssl1.1 DEB ---"
deb_dir="$WORK/deb-build"
mkdir -p "$deb_dir/DEBIAN" "$deb_dir/usr/lib"
cat > "$deb_dir/DEBIAN/control" <<CTRL
Package: libssl1.1
Version: 1.1.1n-0
Section: libs
Priority: optional
Architecture: amd64
Maintainer: Test <test@example.com>
Description: Minimal test libssl package
 Minimal DEB for integration testing.
CTRL
echo "libssl placeholder" > "$deb_dir/usr/lib/libssl.so.1.1"
dpkg-deb --build "$deb_dir" "$WORK/libssl1.1_1.1.1n-0_amd64.deb" 2>/dev/null
echo "  Created libssl1.1_1.1.1n-0_amd64.deb"

# ─── 7. client-setup.msi ───
echo "--- Building client-setup.msi ---"
msi_dir="$WORK/msi-build"
mkdir -p "$msi_dir"

# Create tiny placeholder files for the MSI payload
echo "MZ client.exe placeholder" > "$msi_dir/client.exe"
echo "MZ sign-plugin.ocx placeholder" > "$msi_dir/sign-plugin.ocx"

cat > "$msi_dir/client-setup.wxs" <<'WXS'
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="12345678-1234-1234-1234-123456789012"
           Name="Vendor FatClient"
           Language="1033"
           Version="3.2.0.0"
           Manufacturer="Vendor Corp"
           UpgradeCode="ABCDEF01-2345-6789-ABCD-EF0123456789">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />
    <MediaTemplate EmbedCab="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="VendorDir" Name="Vendor">
          <Directory Id="INSTALLDIR" Name="FatClient">
            <Component Id="ClientExe" Guid="11111111-1111-1111-1111-111111111111">
              <File Id="ClientExeFile" Source="client.exe" KeyPath="yes" />
            </Component>
            <Directory Id="PluginsDir" Name="plugins">
              <Component Id="SignPlugin" Guid="22222222-2222-2222-2222-222222222222">
                <File Id="SignPluginFile" Source="sign-plugin.ocx" KeyPath="yes" />
              </Component>
            </Directory>
          </Directory>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Complete" Level="1">
      <ComponentRef Id="ClientExe" />
      <ComponentRef Id="SignPlugin" />
    </Feature>
  </Product>
</Wix>
WXS
(cd "$msi_dir" && wixl -o "$WORK/client-setup.msi" client-setup.wxs 2>/dev/null)
echo "  Created client-setup.msi"

# ─── 8. vcredist.cab ───
echo "--- Building vcredist.cab ---"
cab_dir="$WORK/cab-build"
mkdir -p "$cab_dir"
echo "vcredist placeholder binary" > "$cab_dir/vcredist_x64.dll"
gcab -cn "$WORK/vcredist.cab" "$cab_dir/vcredist_x64.dll" 2>/dev/null
echo "  Created vcredist.cab"

# ─── 9. InstallShield data1.cab + data1.hdr ───
echo "--- Building InstallShield stubs ---"
# Create a minimal file with ISc( magic bytes. Real unshield extraction
# will fail on this, but that's expected — the test verifies format
# detection and the correct skip of .hdr files.
printf 'ISc(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' > "$WORK/data1.cab"
# Pad to at least 300 bytes so identify can read a header
dd if=/dev/zero bs=1 count=284 >> "$WORK/data1.cab" 2>/dev/null
# The .hdr companion is just a header file, not extractable
printf '\x00\x00\x00\x00' > "$WORK/data1.hdr"
dd if=/dev/zero bs=1 count=296 >> "$WORK/data1.hdr" 2>/dev/null
echo "  Created data1.cab + data1.hdr (InstallShield stubs)"

# ─── 10. webapp-patch-1.2.1.7z ───
echo "--- Building webapp-patch-1.2.1.7z ---"
webapp_dir="$WORK/webapp-build/webapp"
mkdir -p "$webapp_dir/node_modules/minimist"

# Bare file copy of minimist (no package.json alongside)
cat > "$webapp_dir/index.js" <<'JS'
module.exports = function (args, opts) {
    // Stripped-down placeholder representing minimist@0.0.8
    return {};
};
JS

# Properly packaged minimist inside node_modules
cat > "$webapp_dir/node_modules/minimist/package.json" <<'JSON'
{
  "name": "minimist",
  "version": "0.0.8",
  "description": "parse argument options",
  "main": "index.js",
  "license": "MIT"
}
JSON
cat > "$webapp_dir/node_modules/minimist/index.js" <<'JS'
module.exports = function (args, opts) {
    // Stripped-down placeholder representing minimist@0.0.8
    return {};
};
JS

# package-lock.json so Syft's javascript-lock-cataloger detects minimist
cat > "$webapp_dir/package-lock.json" <<'JSON'
{
  "name": "webapp",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "minimist": {
      "version": "0.0.8",
      "resolved": "https://registry.npmjs.org/minimist/-/minimist-0.0.8.tgz"
    }
  }
}
JSON

7zz a -mx=1 "$WORK/webapp-patch-1.2.1.7z" "$WORK/webapp-build/webapp" >/dev/null 2>&1
echo "  Created webapp-patch-1.2.1.7z"

# ─── 11. release-notes.pdf ───
echo "--- Building release-notes.pdf ---"
cat > "$WORK/release-notes.pdf" <<'PDF'
%PDF-1.0
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
190
%%EOF
PDF
echo "  Created release-notes.pdf"

# ─── 12. Assemble vendor-suite-3.2.zip ───
echo "--- Assembling vendor-suite-3.2.zip ---"
suite_dir="$WORK/vendor-suite"
mkdir -p "$suite_dir/linux"
mkdir -p "$suite_dir/windows/prereqs"
mkdir -p "$suite_dir/windows/legacy-addon"
mkdir -p "$suite_dir/web"
mkdir -p "$suite_dir/docs"

cp "$WORK/server-3.2.rpm"                       "$suite_dir/linux/"
cp "$WORK/libssl1.1_1.1.1n-0_amd64.deb"         "$suite_dir/linux/"
cp "$WORK/apache-tomcat-9.0.98.tar.gz"           "$suite_dir/linux/"
cp "$WORK/resources.tgz"                         "$suite_dir/linux/"
cp "$WORK/client-setup.msi"                      "$suite_dir/windows/"
cp "$WORK/vcredist.cab"                          "$suite_dir/windows/prereqs/"
cp "$WORK/data1.cab"                             "$suite_dir/windows/legacy-addon/"
cp "$WORK/data1.hdr"                             "$suite_dir/windows/legacy-addon/"
cp "$WORK/webapp-patch-1.2.1.7z"                 "$suite_dir/web/"
cp "$WORK/release-notes.pdf"                     "$suite_dir/docs/"

(cd "$suite_dir" && zip -qr "$TESTDATA/vendor-suite-3.2.zip" .)
echo "  Created testdata/vendor-suite-3.2.zip"

echo ""
echo "=== Done ==="
ls -lh "$TESTDATA/vendor-suite-3.2.zip"
