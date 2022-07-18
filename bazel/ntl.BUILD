package(
    default_visibility = [
        "//visibility:public",
    ],
)
cc_library(
    name = "ntl",
    hdrs = glob(["include/**/*.h"]),
    srcs = ["libntl.a"] + glob(["include/**/*.h"]),
    includes = ["include"],
    linkopts = ["-lpthread", "-ldl"],
    visibility = ["//visibility:public"],
)

genrule(
    name = "ntl-build",
    srcs = glob(["**/*"],
    exclude=["bazel-*"]),
    outs = [
        "libntl.a",
    ],
    cmd = """
        set -x
        NTL_ROOT=$$(dirname $(location src))
        pushd $$NTL_ROOT 
            ./configure
            make
        popd
        cp $$NTL_ROOT/libntl.a $(location libntl.a)
    """,
)
