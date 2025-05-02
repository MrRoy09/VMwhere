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

ENTRYPOINT ["/bin/out"]

FROM scratch AS export
COPY --from=builder /app/build/out /out
