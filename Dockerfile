# syntax=docker/dockerfile:1

ARG GO_VERSION=1.27.0

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -ldflags="-s -w" -o /out/arcane-bw-runner .

FROM debian:bookworm-slim AS bitwarden
ARG TARGETARCH
ARG BW_VERSION=2026.8.0
ARG BW_SHA256_AMD64=367f618e9fcccaac4980ec12c7bafd01df739b5f3cb1af31bc9045cf75eea1d6
ARG BW_SHA256_ARM64=74d822a5dceda5896ed8fc07bc61925b29afd98d96a6a3e9e525ae556c3083a8
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl unzip \
    && case "$TARGETARCH" in \
         amd64) archive="bw-linux-${BW_VERSION}.zip"; digest="$BW_SHA256_AMD64" ;; \
         arm64) archive="bw-linux-arm64-${BW_VERSION}.zip"; digest="$BW_SHA256_ARM64" ;; \
         *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
       esac \
    && curl --fail --location --silent --show-error \
         --output /tmp/bw.zip \
         "https://github.com/bitwarden/clients/releases/download/cli-v${BW_VERSION}/${archive}" \
    && echo "$digest  /tmp/bw.zip" | sha256sum --check --strict \
    && unzip -q /tmp/bw.zip -d /out \
    && chmod 0755 /out/bw

FROM debian:bookworm-slim
ARG BW_VERSION=2026.8.0
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libatomic1 libgcc-s1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 1000 -g 1000 -m 0700 /home/runner \
    && install -d -o 1000 -g 1000 -m 0755 /workspace
COPY --from=build /out/arcane-bw-runner /usr/local/bin/arcane-bw-runner
COPY --from=bitwarden /out/bw /usr/local/bin/bw
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/arcane-bw-runner/THIRD_PARTY_NOTICES.md
RUN test "$(/usr/local/bin/bw --version)" = "$BW_VERSION" \
    && test -f /usr/share/common-licenses/GPL-3
ENV HOME=/home/runner
USER 1000:1000
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/arcane-bw-runner"]
