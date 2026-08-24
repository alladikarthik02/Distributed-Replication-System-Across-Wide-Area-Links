# wanrep — reproducible build/test environment.
#
# WHY A CONTAINER AT ALL:
#   Every correctness claim in this project is about OS behaviour: short writes on
#   sockets, SIGPIPE on a dead peer, the difference between an orderly close (read
#   returns 0) and an abortive one (ECONNRESET), fsync ordering, atomic rename,
#   flock. macOS and Linux disagree on several of these -- SO_NOSIGPIPE vs
#   MSG_NOSIGNAL is only the most visible. Pinning the OS is correctness, not tidiness.
#
# WHY UBUNTU 24.04:
#   glibc 2.39 + GCC 13 -- full C++20 (std::span, jthread, <bit>, barriers) without a
#   toolchain scavenger hunt, and a mainstream LTS a reviewer can reproduce exactly.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Toolchain, plus the tools we will actually need when this breaks at 2am:
#   gdb              - thread stacks for a deadlock, a corrupt frame header
#   valgrind         - memcheck/helgrind as a second opinion to the sanitizers
#   strace           - which syscall returned the short write, and what errno
#   iproute2         - `tc netem`: real-kernel latency, to cross-check WanLink (SPEC 3.8)
#   iputils-ping     - baseline loopback RTT before we start emulating one
#   netcat/tcpdump   - poking at the wire when our own framing is the suspect
#   binutils/xxd     - hexdump forensics on our own frames and chunk records
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      g++ \
      cmake \
      ninja-build \
      gdb \
      valgrind \
      strace \
      iproute2 \
      iputils-ping \
      netcat-openbsd \
      tcpdump \
      binutils \
      file \
      xxd \
      python3 \
      git \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Root inside a throwaway, network-isolated dev container. Documented so it reads as a
# decision, not an oversight: we need to SIGKILL our own child processes in the fault
# tests, and `tc qdisc` needs NET_ADMIN.
CMD ["/bin/bash"]
