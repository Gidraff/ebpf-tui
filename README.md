# ebpf-tui

## Prerequisites
Install `limactl`

#### Running on MacOs using Limactl

Use brew to install `limactl`.
```shell
brew install limactl
```

Then, run `limactl start` to start lima (default VM) or
create an instance from Ubuntu template: 
```shell 
limactl create --name=ubuntu template://ubuntu
```

To open a shell inside the VM:
```shell 
limactl shell <instance-name>
```

Inside the VM, run the following commands to update the instance and install Rust dependencies and libraries.
```shell
sudo apt update

sudo apt install -y rustup net-tools build-essential pkg-config libssl-dev
```

Install Rust toolchain:
```shell
rustup toolchain install nightly --component rust-src

rustup target add bpfel-unknown-none

# Install bpf-linker
cargo install bpf-linker
```

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
# Build the eBPF program that runs on the Kernel
cargo build --package ebpf-tui-ebpf --target bpfel-unknown-none -Z build-std=core

# Build User-space application
cargo build --package ebpf-tui

# List the available Network interfaces:
iconfig 

# Run the User application:
sudo ./target/debug/ebpf-tui --iface eth0
```

## License

With the exception of eBPF code, ebpf-tui is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
