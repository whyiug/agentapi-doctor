FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .

ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown
RUN mkdir -p /out/work /out/registry-data && \
		chown 65532:65532 /out/work /out/registry-data && \
		ldflags="-s -w -X github.com/whyiug/agentapi-doctor/internal/buildinfo.Version=${VERSION} -X github.com/whyiug/agentapi-doctor/internal/buildinfo.Commit=${COMMIT} -X github.com/whyiug/agentapi-doctor/internal/buildinfo.BuiltAt=${BUILT_AT}" && \
		CGO_ENABLED=0 GOPROXY=off GOSUMDB=off go build -mod=vendor -trimpath -buildvcs=true \
	      -ldflags "$ldflags" \
	      -o /out/doctor ./cmd/doctor && \
		CGO_ENABLED=0 GOPROXY=off GOSUMDB=off go build -mod=vendor -trimpath -buildvcs=true -ldflags "$ldflags" -o /out/registry ./cmd/registry && \
		CGO_ENABLED=0 GOPROXY=off GOSUMDB=off go build -mod=vendor -trimpath -buildvcs=true -ldflags "$ldflags" -o /out/reference-server ./cmd/reference-server

FROM scratch AS doctor
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="AgentAPI Doctor" \
      org.opencontainers.image.description="Evidence-first Agent API compatibility laboratory" \
      org.opencontainers.image.source="https://github.com/whyiug/agentapi-doctor" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/work /work
COPY --from=build /out/doctor /usr/local/bin/doctor
COPY --from=build /src/LICENSE /licenses/LICENSE
COPY --from=build /src/NOTICE /licenses/NOTICE
COPY --from=build /src/THIRD_PARTY_LICENSES.txt /licenses/THIRD_PARTY_LICENSES.txt
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/doctor"]

FROM scratch AS registry
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="AgentAPI Doctor Registry" \
      org.opencontainers.image.source="https://github.com/whyiug/agentapi-doctor" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/registry /usr/local/bin/registry
COPY --from=build /src/LICENSE /licenses/LICENSE
COPY --from=build /src/NOTICE /licenses/NOTICE
COPY --from=build /src/THIRD_PARTY_LICENSES.txt /licenses/THIRD_PARTY_LICENSES.txt
COPY --from=build --chown=65532:65532 /out/registry-data /data
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/registry"]

FROM scratch AS reference-server
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="AgentAPI Doctor synthetic reference server" \
      org.opencontainers.image.source="https://github.com/whyiug/agentapi-doctor" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/reference-server /usr/local/bin/reference-server
COPY --from=build /src/LICENSE /licenses/LICENSE
COPY --from=build /src/NOTICE /licenses/NOTICE
COPY --from=build /src/THIRD_PARTY_LICENSES.txt /licenses/THIRD_PARTY_LICENSES.txt
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/reference-server"]
