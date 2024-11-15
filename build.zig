// SPDX-License-Identifier: MPL-2.0
const std = @import("std");

pub fn build(b: *std.Build) !void {
    var o = try Options.make(b);
    const upstream = b.dependency("upstream", .{ .target = o.target, .optimize = o.optimize });
    try o.config(b, upstream);
    if (o.debug) std.debug.print("{}", .{o});

    const shared = try o.getShared(b, upstream);
    if (o.shared) b.installArtifact(shared);

    const static = try o.getStatic(b, upstream);
    if (o.static) b.installArtifact(static);

    const example = b.addExecutable(.{
        .target = o.target,
        .optimize = o.optimize,
        .name = "example",
    });
    example.addCSourceFile(.{ .file = b.path("example.c"), .flags = &.{"-std=c99"} });
    if (o.shared) {
        example.linkLibrary(shared);
    } else {
        example.linkLibrary(static);
    }

    b.step("example", "build example").dependOn(b.getInstallStep());
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

    debug: bool,

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
            .want_tipc = b.option(bool, "tipc", "enable tipc support (false)") orelse false,
            .want_draft = b.option(bool, "draft", "enable draft apis (false)") orelse false,
            .militant_assertions = b.option(bool, "militant", "enable militant assertions (true)") orelse true,
            .poller = b.option(Options.Poller, "poller", "what to use for zmq_poll (auto)"),
            .debug = b.option(bool, "debug", "show options") orelse false,
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
                .freebsd, .openbsd, .netbsd, .macos => .kqueue,
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

        o.ch.addValues(.{ .ZMQ_CACHELINE_SIZE = std.atomic.cacheLineForCpu(o.target.result.cpu) });

        switch (o.target.result.os.tag) {
            .linux => {
                // TODO: actually check versions
                o.ch.addValues(.{ .HAVE_FORK = 1 });
                o.ch.addValues(.{ .HAVE_POSIX_MEMALIGN = 1 });
                o.ch.addValues(.{ .HAVE_MKDTEMP = 1 });
                o.ch.addValues(.{ .HAVE_CLOCK_GETTIME = 1 });
                o.ch.addValues(.{ .HAVE_PPOLL = 1 });
                o.ch.addValues(.{ .ZMQ_IOTHREAD_POLLER_USE_EPOLL_CLOEXEC = 1 });
                o.ch.addValues(.{ .ZMQ_HAVE_UIO = 1 });
                o.ch.addValues(.{ .ZMQ_USE_CV_IMPL_STL11 = 1 });
            },
            .windows => {
                o.ch.addValues(.{ .ZMQ_HAVE_WINDOWS = 1 });
                o.ch.addValues(.{ .HAVE_POSIX_MEMALIGN = 0 });
                o.ch.addValues(.{ .ZMQ_USE_CV_IMPL_WIN32API = 1 });
            },
            .macos => {
                o.ch.addValues(.{ .HAVE_POSIX_MEMALIGN = o.target.result.os.versionRange().semver.isAtLeast(std.SemanticVersion.parse("10.6.0") catch unreachable) });
                o.ch.addValues(.{ .ZMQ_HAVE_UIO = 1 });
                o.ch.addValues(.{ .ZMQ_USE_CV_IMPL_STL11 = 1 });
            },
            // TODO
            else => {
                o.ch.addValues(.{ .HAVE_POSIX_MEMALIGN = 0 });
            },
        }

        o.ch.addValues(.{ .ZMQ_HAVE_STRLCPY = 1 });
        o.ch.addValues(.{ .HAVE_STRNLEN = 1 });

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

    pub fn getStatic(o: Options, b: *std.Build, u: *std.Build.Dependency) !*std.Build.Step.Compile {
        const lib = b.addStaticLibrary(.{
            .name = "zmq",
            .target = o.target,
            .optimize = o.optimize,
        });
        try o.addCpp(u, lib);
        try o.addSystem(b, lib);
        try o.addFeatures(b, lib);
        return lib;
    }

    pub fn getShared(o: Options, b: *std.Build, u: *std.Build.Dependency) !*std.Build.Step.Compile {
        const lib = b.addSharedLibrary(.{
            .name = "zmq",
            .target = o.target,
            .optimize = o.optimize,
        });
        try o.addCpp(u, lib);
        try o.addSystem(b, lib);
        try o.addFeatures(b, lib);
        return lib;
    }

    pub fn addCpp(o: *const Options, u: *std.Build.Dependency, c: *std.Build.Step.Compile) !void {
        const flags = &.{
            "-std=gnu++11",
            "-Wall",
            "-Wextra",
            "-Wno-tautological-compare",
            "-Wno-unused-parameter",
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
                "stream_connecter_base.cpp",
                "stream_listener_base.cpp",
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
            .flags = flags,
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
                .flags = flags,
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
                .flags = flags,
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
                .flags = flags,
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
                .flags = flags,
                .root = u.path("src"),
            });
        }

        c.installHeader(u.path("include/zmq.h"), "zmq.h");
        c.installHeader(u.path("include/zmq_utils.h"), "zmq_utils.h");
        c.addConfigHeader(o.ch);
    }

    fn addSystem(o: *const Options, b: *std.Build, c: *std.Build.Step.Compile) !void {
        c.linkLibC();
        c.linkLibCpp();

        c.defineCMacro("_REENTRANT", null);
        c.defineCMacro("_THREAD_SAFE", null);
        c.defineCMacro("ZMQ_CUSTOM_PLATFORM_HPP", null);

        if (o.target.result.os.tag == .windows) {
            c.linkSystemLibrary2("ws2_32", .{});
            c.linkSystemLibrary2("iphlpapi", .{});
            c.linkSystemLibrary2("rpcrt4", .{});
            // bruh
            var t = o.target;
            t.result.abi = .gnu;
            t.query.abi = .gnu;
            t.query.cpu_model = .baseline;
            t.result.cpu = std.Target.Cpu.baseline(t.result.cpu.arch, t.result.os);

            const m_winpthreads = b.lazyDependency("winpthreads", .{ .target = t, .optimize = o.optimize });
            if (m_winpthreads) |winpthreads| {
                const l = winpthreads.artifact("winpthreads");
                c.linkLibrary(l);
            }

            // I hate Windows
            c.defineCMacro("DLL_EXPORT", "__declspec(dllexport)");
        } else {
            // TODO: determine when this is required
            //c.linkSystemLibrary2("rt", .{  });
        }
    }

    fn addFeatures(o: *const Options, b: *std.Build, s: *std.Build.Step.Compile) !void {
        if (o.want_sodium) {
            if (o.vendor_sodium) {
                const m_sodium = b.lazyDependency("sodium", .{ .shared = false, .target = o.target, .optimize = o.optimize });
                if (m_sodium) |sodium| {
                    // meeeh!
                    const name = if (o.target.result.os.tag == .windows) "libsodium-static" else "sodium";
                    const sodium_s = sodium.artifact(name);

                    s.linkLibrary(sodium_s);
                }
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
