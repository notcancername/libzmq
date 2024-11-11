# libzmq
Zig build system for [libzmq](https://github.com/zeromq/libzmq).

By default, everything is built barebones, with no libraries used. No auto-configuration is performed (yet?).

Compiling tested for Windows, Linux, OS X, all x86_64, with `0.14.0-dev.2210+62f4a6b4d`.

## Building
You'll likely want to configure some options, see below.

```shell-session
$ zig build
```

The artifacts will be ready to install in the `zig-out` directory.

## Using from Zig

- For a more friendly binding to libzmq, see [zlzmq](https://github.com/notcancername/zlzmq).
- For a more high-level API, see [zzmq](https://github.com/nine-lives-later/zzmq).

```shell-session
$ zig fetch --save 'git+https://github.com/notcancername/libzmq#master'
```

```zig
const libzmq_dep = b.dependency("libzmq", .{ .target = target, .optimize = .optimize, .shared = false });
const libzmq = libzmq_dep.artifact("libzmq");
exe.linkLibrary(libzmq);
```

## Build options
### General
- `-Dstatic=true`: Default. Build a static library.
- `-Dshared=true`: Default. Build a shared library.
- `-Dtsan=true`: Use ThreadSanitizer.
- `-Dubsan=true`: Use AddressSanitizer.
### ZMQ features
- `-Dsodium_close_randombytes=true`: Default. Automatically close libsodium randombytes. Not threadsafe without getrandom.
- `-Dmilitant=true`: Default. Enable Militant assertions.
- `-Dtipc=true`: Enable TIPC. Doesn't seem to work for Windows.
- `-Ddraft=true`: Enable draft features.
- `-Dcurve=true`: Enable ZMQ_CURVE support. Requires `-Dsodium=true`.
- `-Dws=true`: WebSocket support. Draft.
- `-Dwss=true`: WebSocket over TLS support. Draft. Requires `-Dgnutls=true`.
- `-Dradix_tree=true`: Radix tree to manage subscriptions. Draft.
- `-Dpoller`: Select a poller implementation.
### Libraries
- `-Dpgm=true`: Use [OpenPGM](https://github.com/steve-o/openpgm) and enable the PGM transport.
- `-Dpgm_name`: Set the name of the OpenPGM library to use.
- `-Dnorm=true`: Use [NORM](https://github.com/USNavalResearchLaboratory/norm) and enable the NORM transport.
- `-Dnss=true`: Use [libnss](https://github.com/nss-dev/nss) for SHA-2 instead of internal code.
- `-Dnss_name`: Set the name of the NSS library to use.
- `-Dsodium=true`: Use [libsodium](https://github.com/jedisct1/libsodium) for CURVE authentication.
- `-Dvendor_sodium=true`: Link a self-built static library instead of linking the system
  library. This is not recommended for security, as it is impossible to update the library, but it
  may be convenient.
- `-Dgnutls=true`: Use [GnuTLS](https://gnutls.org/) for secure WebSockets.
- `-Dgssapi_krb5=true`: Use [libgssapi_krb5](https://github.com/estokes/libgssapi) for GSSAPI
  authentication.
- `-Dlibbsd=true`: Use [libbsd](https://github.com/JackieXie168/libbsd) for strlcpy.
- `-Dvmci=true` Use VMCI.

All libraries have `_lib_dir` and `_inc_dir` options, which you may use to set the path to the
library and header files respectively.
