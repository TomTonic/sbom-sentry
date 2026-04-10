FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        jq \
        p7zip-full \
        unshield \
    && if [ ! -x /usr/bin/7zz ] && [ -x /usr/bin/7z ]; then ln -s /usr/bin/7z /usr/local/bin/7zz; fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sbom-sentry

COPY dist/sbom-sentry-linux-amd64 /opt/sbom-sentry/sbom-sentry
COPY .github/release-test/run-release-test.sh /opt/sbom-sentry/run-release-test.sh
COPY .github/release-test/expected-delivery-paths.txt /opt/sbom-sentry/testdata/expected-delivery-paths.txt
COPY integration/testdata/release/release-happy-path.zip /opt/sbom-sentry/testdata/release-happy-path.zip

RUN chmod +x /opt/sbom-sentry/sbom-sentry /opt/sbom-sentry/run-release-test.sh

ENTRYPOINT ["/opt/sbom-sentry/run-release-test.sh"]
