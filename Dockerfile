FROM golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY cmd/browser-attested-object-controller/ ./cmd/browser-attested-object-controller/
RUN go vet ./... && go test -count=1 -timeout=120s ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/browser-attested-object-controller ./cmd/browser-attested-object-controller

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates util-linux \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 browser \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /workspace browser \
 && mkdir /workspace && chown 10001:10001 /workspace && chmod 0700 /workspace
COPY --from=build /out/browser-attested-object-controller /usr/local/bin/browser-attested-object-controller
COPY --chmod=0555 controller-entrypoint.sh /usr/local/bin/browser-controller-entrypoint
USER 0:0
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/browser-controller-entrypoint"]

FROM build AS test-build
RUN CGO_ENABLED=0 go test -trimpath -ldflags='-s -w' -c -o /out/browser.test .

FROM runtime AS acceptance
COPY --from=test-build /out/browser.test /usr/local/bin/browser.test
COPY --chmod=0555 controller-acceptance.sh /usr/local/bin/browser-attested-object-controller
