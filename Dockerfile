FROM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ucr ./cmd/ucr

FROM alpine:3.23@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63
# exec profiles can only run tools that exist in this image.
RUN apk add --no-cache ca-certificates git openssh-client curl \
 && adduser -D -H -u 10001 ucanrun \
 && mkdir /data && chown 10001:10001 /data && chmod 700 /data
COPY --from=build /ucr /usr/local/bin/ucr
USER 10001:10001
ENV UCANRUN_DATA=/data UCANRUN_WEB_ADDR=0.0.0.0:8780 UCANRUN_AGENT_ADDR=0.0.0.0:8781
EXPOSE 8780 8781
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["wget","-qO-","http://127.0.0.1:8780/healthz"]
ENTRYPOINT ["ucr"]
CMD ["serve"]
