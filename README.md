# `railcar` - rust implementation of the oci-runtime spec #

![railcar](https://github.com/oracle/railcar/raw/master/railcar.png
"railcar")

## What is `railcar`? ##

`railcar` is a rust implementation of the [opencontainers
initiative](https://www.opencontainers.org/)'s [runtime
spec](https://github.com/opencontainers/runtime-spec). It is similar to the
reference implementation `runc`, but it is implemented completely in rust for
memory safety without needing the overhead of a garbage collector or multiple
threads. For more information on the development of railcar, check out
[Building a Container Runtime in
Rust](https://blogs.oracle.com/developers/building-a-container-runtime-in-rust)

## Building `railcar` ##

[![wercker status](https://app.wercker.com/status/730e874772dc02c6005f4ae4e42b0ca4/s/master "wercker status")](https://app.wercker.com/project/byKey/730e874772dc02c6005f4ae4e42b0ca4)

Install rust:

    curl https://sh.rustup.rs -sSf | sh
    cargo install cargo-when
    rustup toolchain install stable-x86_64-unknown-linux-gnu
    rustup default stable-x86_64-unknown-linux-gnu # for stable
    rustup target install x86_64-unknown-linux-musl # for stable
    rustup toolchain install nightly-x86_64-unknown-linux-gnu
    rustup default nightly-x86_64-unknown-linux-gnu # for nightly
    rustup target install x86_64-unknown-linux-musl # for nightly

Building can be done via build.sh:

    build.sh

By default, build.sh builds a dynamic binary using gnu. To build a static
binary, set `TARGET` to `x86_64-unknown-linux-musl`:

    TARGET=x86_64-unknown-linux-musl ./build.sh

Build requirements for TARGET=x86_64-unknown-linux-gnu:

    libseccomp-devel

Build requirements for TARGET=x86_64-unknown-linux-musl:

    git submodule update --init
    autotools
    make
    gcc
    musl-gcc

To build a release version:

    build.sh --release

If you build using stable instead of nightly, the set_name feature will be
disabled and the init process inside the container will not be named rc-init
when viewed via ps or /proc/$pid/cmdline.

## Using `railcar` ##

    ./railcar run

You can specify a different bundle directory where your config.json is
located with -b:

    ./railcar -b /some/other/directory run

## Using `railcar` with docker ##

`railcar` can be used as a backend for docker. To use it, start the docker
daemon with an additional backend:

    dockerd ... --experimental --add-runtime "rc=/path/to/railcar"

Then you can use `railcar` by specifying the `rc` backend:

    docker run -it --rm --runtime rc hello

Note that you should start the daemon with a terminal (the -t option) so that
docker can properly collect stdout and stderr from `railcar`. If you want to
daemonize the container, just use:

    docker run -dt --rm --runtime rc hello

## Differences from `runc` ##

In general, `railcar` is very similar to `runc`, but some of the `runc`
commands are not supported. Currently, `railcar` does not support the following
commands:

     checkpoint
     events
     exec
     init
     list
     pause
     restore
     resume
     spec

Also, `railcar` always runs an init process separately from the container
process.

## Contributing ##

`railcar` is an open source project. See [CONTRIBUTING](CONTRIBUTING.md) for
details.

Oracle gratefully acknowledges the contributions to railcar that have been made
by the community.

## Getting in touch ##

The best way to get in touch is Slack.

Click [here](https://join.slack.com/t/oraclecontainertools/shared_invite/enQtMzIwNzg3NDIzMzE5LTIwMjZlODllMWRmNjMwZGM1NGNjMThlZjg3ZmU3NDY1ZWU5ZGJmZWFkOTBjNzk0ODIxNzQ2ODUyNThiNmE0MmI) to join the the [Oracle Container Tools workspace](https://oraclecontainertools.slack.com).

Then join the [Railcar channel](https://oraclecontainertools.slack.com/messages/C8BP6MEA0).

## License ##

Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.

`railcar` is dual licensed under the Universal Permissive License 1.0 and the
Apache License 2.0.

See [LICENSE](LICENSE.txt) for more details.
