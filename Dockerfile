# syntax=docker/dockerfile:1.7
# One image for the control plane and the runner. Build from this repo with the
# web and modules repos as named contexts (docker-compose.yml does this):
#   docker build --build-context web=../srustiops-web --build-context catalog=../srustiops-modules/catalog -t srustiops .
ARG TOFU_VERSION=1.13.2

# Build stages run on the build machine's own platform and cross-compile for
# the target, so multi-platform images (linux/amd64 and linux/arm64) build at
# native speed instead of under emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH
# The version /healthz reports, which fleet rollouts compare: pass the image tag.
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/srustiops ./cmd/srustiops \
 && mkdir -p /out/certs /out/work

# The web console is static files: built once, identical for every platform.
FROM --platform=$BUILDPLATFORM node:20-alpine AS webbuild
WORKDIR /web
COPY --from=web package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY --from=web . .
RUN npm run build

FROM ghcr.io/opentofu/opentofu:${TOFU_VERSION}-minimal AS tofu

# The catalog's pinned providers for the target platform, mirrored at build
# time on the build machine, so runners install them from disk: no download
# per run, and a registry outage cannot fail a run.
FROM --platform=$BUILDPLATFORM ghcr.io/opentofu/opentofu:${TOFU_VERSION}-minimal AS tofu-native
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS providers
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=tofu-native /usr/local/bin/tofu /usr/local/bin/tofu
COPY --from=catalog . /catalog
RUN CGO_ENABLED=0 go build -o /tmp/srustiops ./cmd/srustiops \
 && /tmp/srustiops providers mirror -catalog /catalog -out /out/providers -platforms linux_$TARGETARCH -tofu /usr/local/bin/tofu

# Control plane: static, distroless, non-root (no shell, no package manager).
FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build /out/srustiops /usr/local/bin/srustiops
COPY --from=webbuild /web/dist /srv/web
COPY --from=catalog . /srv/catalog
# Owned by nonroot so named volumes mounted here start out writable by the service.
COPY --from=build --chown=65532:65532 /out/certs /certs
ENV SRUSTIOPS_WEB_DIR=/srv/web \
    SRUSTIOPS_CATALOG_DIR=/srv/catalog
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/srustiops"]
CMD ["central"]

# Runner: OpenTofu downloads registry modules from their git sources (pinned to a
# commit by the registry), so this image adds git and CA certificates, nothing else.
FROM alpine:3.22 AS runner
RUN apk add --no-cache git ca-certificates \
 && adduser -D -H -u 65532 nonroot
COPY --from=build /out/srustiops /usr/local/bin/srustiops
COPY --from=tofu /usr/local/bin/tofu /usr/local/bin/tofu
COPY --from=catalog . /srv/catalog
COPY --from=providers /out/providers /srv/providers
ENV SRUSTIOPS_CATALOG_DIR=/srv/catalog \
    SRUSTIOPS_PROVIDER_SEED=/srv/providers \
    SRUSTIOPS_TOFU_PATH=/usr/local/bin/tofu \
    SRUSTIOPS_WORK_DIR=/tmp/srustiops
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/srustiops"]
CMD ["runner"]
