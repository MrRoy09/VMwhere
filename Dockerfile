FROM debian:trixie AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    llvm-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ./src src
COPY ./passes passes
COPY ./hooks hooks
COPY ./test test
COPY Makefile Makefile

RUN make build

FROM alpine:latest AS export

COPY --from=builder /app/build /build

ENTRYPOINT ["/bin/ash"]
