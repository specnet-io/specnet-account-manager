# Static Go binary on scratch: small image, no shell, runs as an unprivileged user. See DETAILS.md §Container.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.4-alpine3.23 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/sam . \
 && mkdir -p /out/data

FROM scratch
ARG VERSION=dev
LABEL org.opencontainers.image.title="specnet-account-manager" \
      org.opencontainers.image.description="Self-service accounts and groups for LDAP directories, with OIDC sign-in." \
      org.opencontainers.image.source="https://github.com/specnet-io/specnet-account-manager" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/sam /sam
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV SAM_DATA_DIR=/data SAM_LISTEN=:8080
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s CMD ["/sam", "healthcheck"]
ENTRYPOINT ["/sam"]
CMD ["serve"]
