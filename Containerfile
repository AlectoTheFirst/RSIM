# The images of rsim:
#   rsim          rsim-api, rsim-inventory and rsim
#   rsim-collect  the collector, with the replies of the demo estate in
#                 /usr/share/rsim/demo for `rsim-collect --data /data seed --demo /usr/share/rsim/demo --if-empty`
# Build one with `podman build --target rsim -t rsim .` or through compose.yaml.
# Behind a proxy that signs TLS with its own CA, add `--secret id=ca,src=<CA PEM file>`:
# cargo then trusts that CA and the public roots of the image.

# The browser UI, which rsim-api embeds at build time.
FROM docker.io/library/node:24.22.2-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# The release binaries.
FROM docker.io/library/rust:1.99.1-slim-trixie@sha256:f6c4a35d21dbb3c89d7a8d056c193e94fc09037f2b58dd858b09c39a47dd02d7 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY ui/ ui/
COPY --from=ui /src/ui/dist ui/dist
ENV RSIM_UI_REQUIRED=1
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    --mount=type=secret,id=ca,target=/run/secrets/ca,required=false \
    if [ -s /run/secrets/ca ]; then \
        cat /etc/ssl/certs/ca-certificates.crt /run/secrets/ca > /tmp/ca.pem \
        && export CARGO_HTTP_CAINFO=/tmp/ca.pem; \
    fi \
    && cargo build --release --locked \
        -p rsim-api -p rsim-cli -p rsim-inventory -p rsim-collect \
        --bin rsim-api --bin rsim --bin rsim-inventory --bin rsim-collect \
    && mkdir -p /out/bin /out/data \
    && cp target/release/rsim-api target/release/rsim target/release/rsim-inventory \
          target/release/rsim-collect /out/bin/

# The runtime: the C runtime library only, as the user nonroot (65532).
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc574abe719b6e5c547384defa2f7b1f24af9605d3f618cf852495d8be2 AS runtime
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME /data

FROM runtime AS rsim-collect
COPY --from=build /out/bin/rsim-collect /usr/local/bin/
COPY demo/ /usr/share/rsim/demo/
ENTRYPOINT ["/usr/local/bin/rsim-collect"]
CMD ["--env", "/run/rsim/collect.env", "--data", "/data", "run", "--repeat"]

FROM runtime AS rsim
COPY --from=build /out/bin/rsim-api /out/bin/rsim-inventory /out/bin/rsim /usr/local/bin/
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/rsim-api"]
CMD ["--listen", "0.0.0.0:8787", "--store", "/data"]
