# syntax=docker/dockerfile:1

FROM alpine:3.22
ARG TARGETARCH
RUN apk add --no-cache ca-certificates
COPY bin/linux/${TARGETARCH}/subscription-converter /usr/local/bin/subscription-converter
USER 65532:65532
EXPOSE 9099
ENTRYPOINT ["/usr/local/bin/subscription-converter"]
CMD ["serve", "-config", "/config/config.yaml"]
