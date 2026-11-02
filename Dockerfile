#   docker build .                 # default: slim
#   docker build --target exec .   # with git, ssh and curl
FROM rust:1.99.1-alpine3.23@sha256:9bdc8babc876f1414b51b20ed3acf9432e543afafa9294c560cb59dafc377175 AS build
RUN apk add --no-cache ca-certificates musl-dev gcc
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && touch src/lib.rs \
 && cargo fetch --locked && rm -r src
COPY web ./web
COPY src ./src
# The musl target links statically by default. Setting crt-static through
# RUSTFLAGS would also apply to proc macros and break the build.
RUN cargo build --release --locked --bin ucr \
 && cp target/release/ucr /ucr \
 && mkdir -m 700 /empty-data

# `--target exec` adds the tools that exec profiles run.
FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63 AS exec
RUN apk add --no-cache ca-certificates git openssh-client curl \
 && adduser -D -H -u 10001 ucanrun \
 && mkdir /data && chown 10001:10001 /data && chmod 700 /data
COPY --from=build /ucr /usr/local/bin/ucr
USER 10001:10001
ENV UCANRUN_DATA=/data UCANRUN_WEB_ADDR=0.0.0.0:8780 UCANRUN_AGENT_ADDR=0.0.0.0:8781 UCANRUN_ENABLE_EXEC=1
EXPOSE 8780 8781
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["ucr","health"]
ENTRYPOINT ["ucr"]
CMD ["serve"]

# Default image: the binary and CA roots only, with no shell and no tools. It
# can call APIs and nothing else.
FROM scratch AS slim
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /ucr /usr/local/bin/ucr
COPY --from=build --chown=10001:10001 /empty-data /data
USER 10001:10001
ENV UCANRUN_DATA=/data UCANRUN_WEB_ADDR=0.0.0.0:8780 UCANRUN_AGENT_ADDR=0.0.0.0:8781
EXPOSE 8780 8781
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["ucr","health"]
ENTRYPOINT ["ucr"]
CMD ["serve"]
