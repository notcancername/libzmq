// SPDX-License-Identifier: MPL-2.0
const std = @import("std");

pub fn build(b: *std.Build) !void {
    var o = try Options.make(b);
    const upstream = b.dependency("upstream", .{ .target = o.target, .optimize = o.optimize });
    try o.config(b, upstream);
    std.debug.print("{}", .{o});
    if (try o.getShared(b, upstream)) |l| b.installArtifact(l);
    if (try o.getStatic(b, upstream)) |l| b.installArtifact(l);
}

// FIXME:
/// The estimated size of the CPU's cache line when atomically updating memory.
/// Add this much padding or align to this boundary to avoid atomically-updated
/// memory from forcing cache invalidations on near, but non-atomic, memory.
///
/// https://en.wikipedia.org/wiki/False_sharing
/// https://github.com/golang/go/search?q=CacheLinePadSize
fn cacheLineForArch(cpu: std.Target.Cpu) u16 {
    return switch (cpu.arch) {
        // x86_64: Starting from Intel's Sandy Bridge, the spatial prefetcher pulls in pairs of 64-byte cache lines at a time.
        // - https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf
        // - https://github.com/facebook/folly/blob/1b5288e6eea6df074758f877c849b6e73bbb9fbb/folly/lang/Align.h#L107
        //
        // aarch64: Some big.LITTLE ARM archs have "big" cores with 128-byte cache lines:
        // - https://www.mono-project.com/news/2016/09/12/arm64-icache/
        // - https://cpufun.substack.com/p/more-m1-fun-hardware-information
        //
        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/arc/Kconfig#L212
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_ppc64x.go#L9
        .x86_64,
        .aarch64,
        .aarch64_be,
        .arc,
        .powerpc64,
        .powerpc64le,
        => 128,

        // https://github.com/llvm/llvm-project/blob/e379094328e49731a606304f7e3559d4f1fa96f9/clang/lib/Basic/Targets/Hexagon.h#L145-L151
        .hexagon,
        => if (std.Target.hexagon.featureSetHas(cpu.features, .v73)) 64 else 32,

        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_arm.go#L7
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_mips.go#L7
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_mipsle.go#L7
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_mips64x.go#L9
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_riscv64.go#L7
        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/sparc/include/asm/cache.h#L14
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        .mips,
        .mipsel,
        .mips64,
        .mips64el,
        .riscv32,
        .riscv64,
        .sparc,
        .sparc64,
        => 32,

        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/m68k/include/asm/cache.h#L10
        .m68k,
        => 16,

        // - https://www.ti.com/lit/pdf/slaa498
        .msp430,
        => 8,

        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_s390x.go#L7
        // - https://sxauroratsubasa.sakura.ne.jp/documents/guide/pdfs/Aurora_ISA_guide.pdf
        .s390x,
        .ve,
        => 256,

        // Other x86 and WASM platforms have 64-byte cache lines.
        // The rest of the architectures are assumed to be similar.
        // - https://github.com/golang/go/blob/dda2991c2ea0c5914714469c4defc2562a907230/src/internal/cpu/cpu_x86.go#L9
        // - https://github.com/golang/go/blob/0a9321ad7f8c91e1b0c7184731257df923977eb9/src/internal/cpu/cpu_loong64.go#L11
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_wasm.go#L7
        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/xtensa/variants/csp/include/variant/core.h#L209
        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/csky/Kconfig#L183
        // - https://www.xmos.com/download/The-XMOS-XS3-Architecture.pdf
        else => 64,
    };
}

pub const Options = struct {
    pub const Poller = enum {
        kqueue,
        epoll,
        devpoll,
        pollset,
        poll,
        select,
    };

    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    static: bool,
    shared: bool,
    linkage: ?std.builtin.LinkMode,

    tsan: bool,
    ubsan: bool,

    want_norm: bool,
    want_tipc: bool,
    want_draft: bool,
    want_pgm: bool,
    want_vmci: bool,
    want_radix_tree: bool,
    want_ws: bool,
    want_wss: bool,
    want_nss: bool,
    want_gnutls: bool,
    want_libbsd: bool,
    want_sodium: bool,
    want_gssapi_krb5: bool,
    sodium_close_randombytes: bool,
    want_curve: bool,
    vendor_sodium: bool,
    militant_assertions: bool,
    poller: ?Poller,

    pgm_name: []const u8 = "pgm",
    pgm_lib_dir: ?[]const u8 = null,
    pgm_inc_dir: ?[]const u8 = null,

    nss_name: []const u8 = "nss3",
    nss_lib_dir: ?[]const u8 = null,
    nss_inc_dir: ?[]const u8 = null,

    gnutls_lib_dir: ?[]const u8 = null,
    gnutls_inc_dir: ?[]const u8 = null,

    libbsd_lib_dir: ?[]const u8 = null,
    libbsd_inc_dir: ?[]const u8 = null,

    sodium_lib_dir: ?[]const u8 = null,
    sodium_inc_dir: ?[]const u8 = null,

    gssapi_krb5_lib_dir: ?[]const u8 = null,
    gssapi_krb5_inc_dir: ?[]const u8 = null,

    norm_lib_dir: ?[]const u8 = null,
    norm_inc_dir: ?[]const u8 = null,

    ch: *std.Build.Step.ConfigHeader = undefined,

    pub fn format(value: Options, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        inline for (&.{
            "optimize",
            "static",
            "shared",
            "linkage",
            "tsan",
            "ubsan",
            "want_norm",
            "want_tipc",
            "want_draft",
            "want_pgm",
            "want_vmci",
            "want_radix_tree",
            "want_ws",
            "want_wss",
            "want_nss",
            "want_gnutls",
            "want_libbsd",
            "want_sodium",
            "want_gssapi_krb5",
            "sodium_close_randombytes",
            "want_curve",
            "vendor_sodium",
            "militant_assertions",
            "poller",
            "pgm_name",
            "pgm_lib_dir",
            "pgm_inc_dir",
            "nss_name",
            "nss_lib_dir",
            "nss_inc_dir",
            "gnutls_lib_dir",
            "gnutls_inc_dir",
            "libbsd_lib_dir",
            "libbsd_inc_dir",
            "sodium_lib_dir",
            "sodium_inc_dir",
            "gssapi_krb5_lib_dir",
            "gssapi_krb5_inc_dir",
        }) |f| {
            const ti = comptime @typeInfo(@TypeOf(@field(@as(Options, undefined), f)));
            const fmt = switch (ti) {
                .pointer => |p| switch (p.size) {
                    .Slice => "s",
                    else => "",
                },
                .optional => |o| switch (o.child) {
                    []const u8 => "?s",
                    else => "?",
                },
                else => "",
            };
            try writer.print("{s: <25} {" ++ fmt ++ "}\n", .{ f, @field(value, f) });
        }
    }

    pub fn make(b: *std.Build) !Options {
        var o: Options = .{
            .target = b.standardTargetOptions(.{}),
            .optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast }),
            .ubsan = b.option(bool, "ubsan", "use UBSanitizer (false)") orelse false,
            .tsan = b.option(bool, "tsan", "use ThreadSanitizer (false)") orelse false,
            .shared = b.option(bool, "shared", "build shared library (true)") orelse true,
            .static = b.option(bool, "static", "build static library (true)") orelse true,
            .linkage = b.option(std.builtin.LinkMode, "linkage", "how to link shared library"),
            .want_norm = b.option(bool, "norm", "link with norm (false)") orelse false,
            .want_pgm = b.option(bool, "pgm", "link with system libpgm (false)") orelse false,
            .want_ws = b.option(bool, "ws", "enable websocket support, draft (false)") orelse false,
            .want_nss = b.option(bool, "nss", "link with system libnss for sha1 (false)") orelse false,
            .want_gnutls = b.option(bool, "gnutls", "link with system gnutls for tls and sha1 (false)") orelse false,
            .want_vmci = b.option(bool, "vmci", "enable vmci support (false)") orelse false,
            .want_libbsd = b.option(bool, "libbsd", "link with system libbsd for strlcpy (false)") orelse false,
            .want_wss = b.option(bool, "wss", "enable websocket over tls support (false)") orelse false,
            .want_radix_tree = b.option(bool, "radix_tree", "enable radix tree to manage subscriptions, draft (false)") orelse false,
            .want_sodium = b.option(bool, "sodium", "link with libsodium for CURVE (false)") orelse false,
            .vendor_sodium = b.option(bool, "vendor_sodium", "link with vendored libsodium instead of system for CURVE (false)") orelse false,
            .sodium_close_randombytes = b.option(bool, "sodium_close_randombytes", "automatically close libsodium randombytes, thread-unsafe without getrandom (true)") orelse true,
            .want_curve = b.option(bool, "curve", "enable CURVE security (false)") orelse false,
            .want_gssapi_krb5 = b.option(bool, "gssapi_krb5", "link system libgssapi_krb5 (false)") orelse false,
            .want_tipc = b.option(bool, "tipc", "enable tipc support (true)") orelse true,
            .want_draft = b.option(bool, "draft", "enable draft apis (false)") orelse false,
            .militant_assertions = b.option(bool, "militant", "enable militant assertions (true)") orelse true,
            .poller = b.option(Options.Poller, "poller", "what to use for zmq_poll (auto)"),
        };

        if (o.want_ws and o.want_wss and !o.want_gnutls) return error.GnutlsRequired;
        if (o.want_curve and !o.want_sodium) return error.SodiumRequired;
        if ((o.want_ws or o.want_radix_tree) and !o.want_draft) return error.DraftRequired;

        inline for (@typeInfo(Options).@"struct".fields) |f| if (comptime std.mem.endsWith(u8, f.name, "_dir") or std.mem.endsWith(u8, f.name, "_name")) {
            if (b.option([]const u8, f.name, "")) |x| @field(o, f.name) = x;
        };

        if (o.poller == null) {
            o.poller = switch (o.target.result.os.tag) {
                .linux => .epoll,
                .freebsd, .openbsd, .netbsd => .kqueue,
                else => .select, // TODO
            };
        }

        return o;
    }

    pub fn config(o: *Options, b: *std.Build, u: *std.Build.Dependency) !void {
        o.ch = b.addConfigHeader(.{ .style = .{ .cmake = u.path("builds/cmake/platform.hpp.in") }, .include_path = "platform.hpp" }, .{});

        switch (o.poller.?) {
            .select => o.ch.addValues(.{ .ZMQ_POLL_BASED_ON_SELECT = 1 }),
            .poll,
            .epoll,
            .devpoll,
            .pollset,
            .kqueue,
            => o.ch.addValues(.{ .ZMQ_POLL_BASED_ON_POLL = 1 }),
        }

        switch (o.poller.?) {
            .select => o.ch.addValues(.{ .ZMQ_IOTHREAD_POLLER_USE_SELECT = 1 }),
            .poll => o.ch.addValues(.{ .ZMQ_IOTHREAD_POLLER_USE_POLL = 1 }),
            .epoll => o.ch.addValues(.{ .ZMQ_IOTHREAD_POLLER_USE_EPOLL = 1 }),
            .devpoll => o.ch.addValues(.{ .ZMQ_IOTHREAD_POLLER_USE_DEVPOLL = 1 }),
            .pollset => o.ch.addValues(.{ .ZMQ_IOTHREAD_POLLER_USE_POLLSET = 1 }),
            .kqueue => o.ch.addValues(.{ .ZMQ_IOTHREAD_POLLER_USE_KQUEUE = 1 }),
        }

        o.ch.addValues(.{ .ZMQ_USE_CV_IMPL_STL11 = 1 });

        switch (o.target.result.os.tag) {
            .linux => {
                // TODO: actually check versions
                o.ch.addValues(.{ .HAVE_FORK = 1 });
                o.ch.addValues(.{ .HAVE_POSIX_MEMALIGN = 1 });
                o.ch.addValues(.{ .HAVE_MKDTEMP = 1 });
                o.ch.addValues(.{ .HAVE_CLOCK_GETTIME = 1 });
                o.ch.addValues(.{ .ZMQ_CACHELINE_SIZE = cacheLineForArch(o.target.result.cpu) });
                o.ch.addValues(.{ .ZMQ_IOTHREAD_POLLER_USE_EPOLL_CLOEXEC = 1 });
            },
            .windows => {
                o.ch.addValues(.{ .ZMQ_HAVE_WINDOWS = 1 });
            },
            // TODO
            else => {},
        }

        o.ch.addValues(.{ .ZMQ_HAVE_STRLCPY = 1 });
        o.ch.addValues(.{ .HAVE_STRNLEN = 1 });
        o.ch.addValues(.{ .ZMQ_HAVE_UIO = 1 });

        if (o.want_radix_tree) o.ch.addValues(.{ .ZMQ_USE_RADIX_TREE = 1 });
        if (o.want_vmci) o.ch.addValues(.{ .ZMQ_HAVE_VMCI = 1 });
        if (o.want_tipc) o.ch.addValues(.{ .ZMQ_HAVE_TIPC = 1 });
        if (o.want_norm) o.ch.addValues(.{ .ZMQ_HAVE_NORM = 1 });
        if (o.want_ws) o.ch.addValues(.{ .ZMQ_HAVE_WS = 1 });
        if (o.want_pgm) o.ch.addValues(.{ .ZMQ_HAVE_OPENPGM = 1 });
        if (o.want_nss) o.ch.addValues(.{ .ZMQ_USE_NSS = 1 });
        if (o.want_gnutls) o.ch.addValues(.{ .ZMQ_USE_GNUTLS = 1 });
        if (o.want_ws and o.want_wss) o.ch.addValues(.{ .ZMQ_HAVE_WSS = 1 });
        if (o.want_libbsd) o.ch.addValues(.{ .ZMQ_HAVE_LIBBSD = 1 });
        if (o.want_gssapi_krb5) o.ch.addValues(.{ .ZMQ_HAVE_LIBGSSAPI_KRB5 = 1 });
        if (!o.want_gnutls and !o.want_nss) o.ch.addValues(.{ .ZMQ_USE_BUILTIN_SHA1 = 1 });
        if (o.militant_assertions) o.ch.addValues(.{ .ZMQ_ACT_MILITANT = 1 });
        if (o.sodium_close_randombytes) o.ch.addValues(.{ .ZMQ_LIBSODIUM_RANDOMBYTES_CLOSE = 1 });
        if (o.want_sodium) o.ch.addValues(.{ .ZMQ_USE_LIBSODIUM = 1 });
        if (o.want_curve) o.ch.addValues(.{ .ZMQ_HAVE_CURVE = 1 });
        if (o.want_draft) o.ch.addValues(.{ .ZMQ_BUILD_DRAFT_API = 1 });
    }

    pub fn getStatic(o: Options, b: *std.Build, u: *std.Build.Dependency) !?*std.Build.Step.Compile {
        if (!o.static) return null;

        const lib = b.addStaticLibrary(.{
            .name = "zmq",
            .target = o.target,
            .optimize = o.optimize,
        });
        try o.addCpp(u, lib);
        try o.addFeatures(b, lib);
        return lib;
    }

    pub fn getShared(o: Options, b: *std.Build, u: *std.Build.Dependency) !?*std.Build.Step.Compile {
        if (!o.shared) return null;

        const lib = b.addSharedLibrary(.{
            .name = "zmq",
            .target = o.target,
            .optimize = o.optimize,
        });
        try o.addCpp(u, lib);
        try o.addFeatures(b, lib);
        return lib;
    }

    pub fn addCpp(o: *const Options, u: *std.Build.Dependency, c: *std.Build.Step.Compile) !void {
        const flags = .{
            "-Wno-tautological-compare",
            "-std=gnu++11",
            "-Wall",
            "-Wextra",
        };

        c.addCSourceFiles(.{
            .files = &.{
                "precompiled.cpp",
                "address.cpp",
                "channel.cpp",
                "client.cpp",
                "clock.cpp",
                "ctx.cpp",
                "curve_mechanism_base.cpp",
                "curve_client.cpp",
                "curve_server.cpp",
                "dealer.cpp",
                "devpoll.cpp",
                "dgram.cpp",
                "dist.cpp",
                "endpoint.cpp",
                "epoll.cpp",
                "err.cpp",
                "fq.cpp",
                "io_object.cpp",
                "io_thread.cpp",
                "ip.cpp",
                "ipc_address.cpp",
                "ipc_connecter.cpp",
                "ipc_listener.cpp",
                "kqueue.cpp",
                "lb.cpp",
                "mailbox.cpp",
                "mailbox_safe.cpp",
                "mechanism.cpp",
                "mechanism_base.cpp",
                "metadata.cpp",
                "msg.cpp",
                "mtrie.cpp",
                "norm_engine.cpp",
                "object.cpp",
                "options.cpp",
                "own.cpp",
                "null_mechanism.cpp",
                "pair.cpp",
                "peer.cpp",
                "pgm_receiver.cpp",
                "pgm_sender.cpp",
                "pgm_socket.cpp",
                "pipe.cpp",
                "plain_client.cpp",
                "plain_server.cpp",
                "poll.cpp",
                "poller_base.cpp",
                "polling_util.cpp",
                "pollset.cpp",
                "proxy.cpp",
                "pub.cpp",
                "pull.cpp",
                "push.cpp",
                "random.cpp",
                "raw_encoder.cpp",
                "raw_decoder.cpp",
                "raw_engine.cpp",
                "reaper.cpp",
                "rep.cpp",
                "req.cpp",
                "router.cpp",
                "select.cpp",
                "server.cpp",
                "session_base.cpp",
                "signaler.cpp",
                "socket_base.cpp",
                "socks.cpp",
                "socks_connecter.cpp",
                "stream.cpp",
                "stream_engine_base.cpp",
                "sub.cpp",
                "tcp.cpp",
                "tcp_address.cpp",
                "tcp_connecter.cpp",
                "tcp_listener.cpp",
                "thread.cpp",
                "trie.cpp",
                "radix_tree.cpp",
                "v1_decoder.cpp",
                "v1_encoder.cpp",
                "v2_decoder.cpp",
                "v2_encoder.cpp",
                "v3_1_encoder.cpp",
                "xpub.cpp",
                "xsub.cpp",
                "zmq.cpp",
                "zmq_utils.cpp",
                "decoder_allocators.cpp",
                "socket_poller.cpp",
                "timers.cpp",
                "radio.cpp",
                "dish.cpp",
                "udp_engine.cpp",
                "udp_address.cpp",
                "scatter.cpp",
                "gather.cpp",
                "ip_resolver.cpp",
                "zap_client.cpp",
                "zmtp_engine.cpp",
            },
            .flags = &flags,
            .root = u.path("src"),
        });

        if (o.want_vmci) {
            c.addCSourceFiles(.{
                .files = &.{
                    "vmci_address.cpp",
                    "vmci_connecter.cpp",
                    "vmci_listener.cpp",
                    "vmci.cpp",
                },
                .flags = &flags,
                .root = u.path("src"),
            });
        }

        if (o.want_tipc) {
            c.addCSourceFiles(.{
                .files = &.{
                    "tipc_address.cpp",
                    "tipc_connecter.cpp",
                    "tipc_listener.cpp",
                },
                .flags = &flags,
                .root = u.path("src"),
            });
        }

        if (o.want_gssapi_krb5) {
            c.addCSourceFiles(.{
                .files = &.{
                    "gssapi_client.cpp",
                    "gssapi_mechanism_base.cpp",
                    "gssapi_server.cpp",
                },
                .flags = &flags,
                .root = u.path("src"),
            });
        }

        if (o.want_ws) {
            c.addCSourceFiles(.{
                .files = &.{
                    "ws_address.cpp",
                    "ws_connecter.cpp",
                    "ws_decoder.cpp",
                    "ws_encoder.cpp",
                    "ws_engine.cpp",
                    "ws_listener.cpp",
                },
                .flags = &flags,
                .root = u.path("src"),
            });
        }

        c.linkLibC();
        c.linkLibCpp();

        c.defineCMacro("_REENTRANT", null);
        c.defineCMacro("_THREAD_SAFE", null);
        c.defineCMacro("ZMQ_CUSTOM_PLATFORM_HPP", null);

        if (o.target.result.os.tag == .windows) {
            c.linkSystemLibrary2("ws2_32", .{ .needed = false });
            c.linkSystemLibrary2("ws2", .{ .needed = false });
            c.linkSystemLibrary2("iphlpapi", .{ .needed = false });
            c.linkSystemLibrary2("rpcrt4", .{ .needed = false });
        } else {
            // TODO: determine when this is required
            //c.linkSystemLibrary2("rt", .{ .needed = false });
        }

        c.installHeader(u.path("include/zmq.h"), "zmq.h");
        c.installHeader(u.path("include/zmq_utils.h"), "zmq_utils.h");
        c.addConfigHeader(o.ch);
    }

    fn addFeatures(o: *const Options, b: *std.Build, s: *std.Build.Step.Compile) !void {
        if (o.want_curve and o.want_sodium) {
            if (o.vendor_sodium) {
                const sodium = b.dependency("sodium", .{ .shared = false });
                const sodium_s = sodium.artifact("sodium");
                s.linkLibrary(sodium_s);
            } else {
                if (o.sodium_lib_dir) |d| s.addLibraryPath(.{ .cwd_relative = d });
                if (o.sodium_inc_dir) |d| s.addIncludePath(.{ .cwd_relative = d });
                s.linkSystemLibrary2("sodium", .{});
            }
        }

        if (o.want_pgm) {
            if (o.pgm_lib_dir) |d| s.addLibraryPath(.{ .cwd_relative = d });
            if (o.pgm_inc_dir) |d| s.addIncludePath(.{ .cwd_relative = d });

            // This is done to accomodate the openpgm headers' use of the standard C99 type
            // qualifier restrict, which, *inexplicably*, is not a thing in C++.
            s.defineCMacro("restrict", "__restrict__");

            // TODO: proper searching
            s.linkSystemLibrary2(o.pgm_name, .{});
        }

        if (o.want_nss) {
            if (o.nss_lib_dir) |d| s.addLibraryPath(.{ .cwd_relative = d });
            if (o.nss_inc_dir) |d| s.addIncludePath(.{ .cwd_relative = d });

            // TODO: proper searching
            s.linkSystemLibrary2("nss", .{});
        }

        if (o.want_norm) {
            if (o.norm_lib_dir) |d| s.addLibraryPath(.{ .cwd_relative = d });
            if (o.norm_inc_dir) |d| s.addIncludePath(.{ .cwd_relative = d });

            s.linkSystemLibrary2("norm", .{});
        }

        if (o.want_gnutls) {
            if (o.gnutls_lib_dir) |d| s.addLibraryPath(.{ .cwd_relative = d });
            if (o.gnutls_inc_dir) |d| s.addIncludePath(.{ .cwd_relative = d });

            s.linkSystemLibrary2("gnutls", .{});
        }

        if (o.want_libbsd) {
            if (o.libbsd_lib_dir) |d| s.addLibraryPath(.{ .cwd_relative = d });
            if (o.libbsd_inc_dir) |d| s.addIncludePath(.{ .cwd_relative = d });

            s.linkSystemLibrary2("bsd", .{});
        }

        if (o.want_gssapi_krb5) {
            if (o.gssapi_krb5_lib_dir) |d| s.addLibraryPath(.{ .cwd_relative = d });
            if (o.gssapi_krb5_inc_dir) |d| s.addIncludePath(.{ .cwd_relative = d });

            s.linkSystemLibrary2("gssapi_krb5", .{});
        }
    }
};
