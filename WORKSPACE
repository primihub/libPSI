workspace(name = "libpsi")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")


_ALL_CONTENT = """\
filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
"""

http_archive(
    name = "rules_foreign_cc",
    sha256 = "6041f1374ff32ba711564374ad8e007aef77f71561a7ce784123b9b4b88614fc",
    strip_prefix = "rules_foreign_cc-0.8.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/0.8.0.tar.gz",
)


load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies()


git_repository(
    name = "com_github_nelhage_rules_boost",
    # commit = "1e3a69bf2d5cd10c34b74f066054cd335d033d71",
    branch = "master",
    remote = "https://github.com/primihub/rules_boost.git",
    # shallow_since = "1591047380 -0700",
)

load("@com_github_nelhage_rules_boost//:boost/boost.bzl", "boost_deps")
boost_deps()


http_archive(
    name = "bazel_common",
    url = "https://github.com/google/bazel-common/archive/refs/heads/master.zip",
    strip_prefix = "bazel-common-master",
    sha256 = "7034b3fb6b3051d70f33853fff48b0e931b57e35c6a32bba0280c6f2b6d6ee0c",
)

http_archive(
    name = "bazel_skylib",
    strip_prefix = None,
    url = "https://github.com/bazelbuild/bazel-skylib/releases/download/1.0.2/bazel-skylib-1.0.2.tar.gz",
    sha256 = "97e70364e9249702246c0e9444bccdc4b847bed1eb03c5a3ece4f83dfe6abc44",
)

load("@bazel_skylib//lib:versions.bzl", "versions")

versions.check(minimum_bazel_version = "5.0.0")


# fmt bazle, ref: https://fossies.org/linux/fmt/support/bazel/README.md
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")


# Google dense_hash_set
http_archive(
    name = "google_sparsehash",
    build_file = "//bazel:BUILD.sparsehash",
    strip_prefix = "sparsehash-master",
    urls = ["https://github.com/google/sparsehash/archive/master.zip"],
)

# libpsi
http_archive(
    name = "osu_libpsi",
    build_file = "//bazel:BUILD.libpsi",
    sha256 = "6f021f24136eb177af38af3bf5d53b3592a1fe1e71d1c098318488a85b0afc3a",
    strip_prefix = "libPSI-master",
    urls = ["https://github.com/osu-crypto/libPSI/archive/refs/heads/master.zip"],
)

# libote
http_archive(
    name = "osu_libote",
    build_file = "//bazel:libOTe.BUILD",
    #sha256 = "6f021f24136eb177af38af3bf5d53b3592a1fe1e71d1c098318488a85b0afc3a",
    strip_prefix = "libOTe-master",
    urls = ["https://github.com/osu-crypto/libOTe/archive/refs/heads/master.zip"],
)

# cryptoTools
#http_archive(
#    name = "cryptoTools",
#    build_file = "//bazel:cryptoTools.BUILD",
#    #sha256 = "6f021f24136eb177af38af3bf5d53b3592a1fe1e71d1c098318488a85b0afc3a",
#    strip_prefix = "cryptoTools-2.0",
#    urls = ["https://github.com/yankaili2006/cryptoTools/archive/refs/tags/v2.0.zip"],
#)

new_git_repository(
    name = "cryptoTools",
    build_file = "//bazel:cryptoTools.BUILD",
    # commit = "1e3a69bf2d5cd10c34b74f066054cd335d033d71",
    branch = "master",
    remote = "https://github.com/yankaili2006/cryptoTools.git",
    # shallow_since = "1591047380 -0700",
)

# ntl
#http_archive(
#    name = "ntl",
#    build_file = "//bazel:ntl.BUILD",
#    #sha256 = "6f021f24136eb177af38af3bf5d53b3592a1fe1e71d1c098318488a85b0afc3a",
#    strip_prefix = "ntl-main",
#    urls = ["https://github.com/libntl/ntl/archive/refs/heads/main.zip"],
#)

#git_repository(
#    name = "ntl",
#    # commit = "1e3a69bf2d5cd10c34b74f066054cd335d033d71",
#    branch = "main",
#    remote = "https://github.com/yankaili2006/ntl.git",
#    # shallow_since = "1591047380 -0700",
#)

new_git_repository(
    name = "ntl",
    build_file = "//bazel:ntl.BUILD",
    # commit = "1e3a69bf2d5cd10c34b74f066054cd335d033d71",
    branch = "main",
    remote = "https://github.com/yankaili2006/ntl.git",
    # shallow_since = "1591047380 -0700",
)

new_git_repository(
    name = "toolkit_relic",
    build_file = "//bazel:BUILD.relic",
    remote = "https://github.com/relic-toolkit/relic.git",
    commit = "3f616ad64c3e63039277b8c90915607b6a2c504c",
    shallow_since = "1581106153 -0800",
)
