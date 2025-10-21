default:
    @just --list

arch := if `uname -m` == "x86_64" {
        "-D__TARGET_ARCH_x86"
    } else if  `uname -m`=="aarch64" { 
        "-D__TARGET_ARCH_arm64"
    } else {
        ""
    }
clang_flags :="-g -O2 -mcpu=v2" +" " + arch +" " + "-Wunused-command-line-argument -target bpf"

ebpf:
    clang {{ clang_flags }} -I./ebpf/ \
        -c ./ebpf/netbee.ebpf.c  \
        -o ./target/netbee.o 

ebpf-http:
    clang {{ clang_flags }} -I./ebpf/ \
        -c ./ebpf/netbee-http.ebpf.c  \
        -o ./target/netbee-http.o 

build:
    go build -o target/netbee ./cmd/main.go

build-http:
    go build -o target/netbee-http ./cmd/main-http.go

run: build
    sudo ./target/netbee