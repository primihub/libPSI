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
  sha256 = "484fc0e14856b9f7434072bc2662488b3fe84d7798a5b7c92a1feb1a0fa8d088",
  strip_prefix = "rules_foreign_cc-0.8.0",
  url = "https://primihub.oss-cn-beijing.aliyuncs.com/tools/rules_foreign_cc_cn-0.8.0.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

git_repository(
  name = "com_github_nelhage_rules_boost",
  commit = "81945736a62fa8490d2ab6bb31705bb04ce4bb6c",
  remote = "https://gitee.com/primihub/rules_boost.git",
)

http_archive(
  name = "ladnir_cryptoTools",
  strip_prefix = "cryptoTools",
  urls = [
    "https://primihub.oss-cn-beijing.aliyuncs.com/tools/cryptoTools_aby3_dep.tar.gz",
  ],
)

load("@ladnir_cryptoTools//bazel:preload.bzl", "cryptoTools_preload")
cryptoTools_preload("ladnir_cryptoTools")
load("@ladnir_cryptoTools//bazel:deps.bzl", "cryptoTools_deps")
cryptoTools_deps()

http_archive(
  name = "osu_libote",
  sha256 = "26ab3e3a590556abdc4d810f560bf3c201447be61da80d643120014fae8bdd4a",
  strip_prefix = "libOTe",
  urls = [
    "https://primihub.oss-cn-beijing.aliyuncs.com/tools/lib_ote_aby3_dep_version.tar.gz",
  ],
)
# Google dense_hash_set
http_archive(
  name = "google_sparsehash",
  build_file = "//bazel:BUILD.sparsehash",
  strip_prefix = "sparsehash-master",
  urls = [
    "https://primihub.oss-cn-beijing.aliyuncs.com/tools/sparsehash-master.zip"
  ],
)