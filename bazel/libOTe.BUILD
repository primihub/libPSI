package(
    default_visibility = [
                    "//visibility:public",
        ],
)

genrule(
    name = "libOTe_config_h",
    outs = [
        "libOTe/config.h",
    ],
    cmd = """
        set -x
        tmpdir="libOTe.tmp"
        mkdir -p "$${tmpdir}"
        echo "#pragma once \r\n \
#include \\"libOTe/version.h\\" \r\n \
#define LIBOTE_VERSION (LIBOTE_VERSION_MAJOR * 10000 + LIBOTE_VERSION_MINOR * 100 + LIBOTE_VERSION_PATCH) \r\n \
/* #define ENABLE_BITPOLYMUL ON */ \r\n \
/* #define ENABLE_SIMPLESTOT ON */ \r\n \
/* #define ENABLE_SIMPLESTOT_ASM ON */ \r\n \
#define ENABLE_MR ON \r\n \
#define OENABLE_MR_KYBERN \r\n \
#define ENABLE_NP \r\n \
#define ENABLE_KOS \r\n \
#define ENABLE_IKNP \r\n \
#define ENABLE_SILENTOT \r\n \
#define ENABLE_DELTA_KOS \r\n \
#define ENABLE_DELTA_IKNP \r\n \
#define ENABLE_OOS ON \r\n \
#define ENABLE_KKRT ON \r\n \
#define ENABLE_RR ON \r\n \
#define ENABLE_AKN ON \r\n \
#if defined(ENABLE_SIMPLESTOT_ASM) && defined(_MSC_VER) \r\n \
    #undef ENABLE_SIMPLESTOT_ASM \r\n \
    #pragma message(\\"ENABLE_SIMPLESTOT_ASM should not be defined on windows.\\") \r\n \
#endif \r\n \
#if defined(ENABLE_MR_KYBER) && defined(_MSC_VER) \r\n \
    #undef ENABLE_MR_KYBER \r\n \
    #pragma message(\\"ENABLE_MR_KYBER should not be defined on windows.\\") \r\n \
#endif \r\n \
">"$${tmpdir}"/config.h
        ls -ltrh "$${tmpdir}"
        mv "$${tmpdir}"/config.h $(location libOTe/config.h)
        rm -r -f -- "$${tmpdir}"
    """,
    visibility = ["//visibility:public"],
)


cc_library(
    name = "SimplestOT",
    srcs = glob(
                    ["SimplestOT/*.c"],
                    ["SimplestOT/*.s"],
                ),
    hdrs = glob(
                    ["SimplestOT/*.h"],
                ),
    textual_hdrs = glob(["SimplestOT/*.data"]),
    linkopts = ["-pthread"],
    linkstatic = True,
)

cc_library(
    name = "KyberOT",
    srcs = glob(
                    ["KyberOT/**/*.c"],
                    ["KyberOT/**/*.s"],
                ),
    hdrs = glob(
                    ["KyberOT/**/*.h"],
                ),
    textual_hdrs = glob(["KyberOT/**/*.macros"]),
    copts= ["-mavx2"],
    linkopts = ["-pthread"],
    linkstatic = True,
)

cc_library(
    name = "libOTe",
    srcs = glob(
                    ["libOTe/**/*.cpp"],
                    ["libOTe/**/*.c"],
                ),
    hdrs = [":libOTe_config_h"] + glob(
                    ["libOTe/**/*.h"],
                ),
    includes = ["./", ":libOTe_config_h"],
    copts = ["-std=c++14 -O0 -g -ggdb -rdynamic -maes -msse2 -msse3 -msse4.1 -mpclmul"],
    linkopts = ["-pthread"],
    # strip_include_prefix = "src",
    # Using an empty include_prefix causes Bazel to emit -I instead of -iquote
    # options for the include directory, so that #include <gmp.h> works.
    #include_prefix = "",
    linkstatic = True,
    deps = [
        "@ladnir_cryptoTools//:libcryptoTools",
    ],
)

cc_library(
    name = "libOTe_Tests",
    srcs = glob(
                    ["libOTe_Tests/**/*.cpp"],
                    ["libOTe_Tests/**/*.c"],
                ),
    hdrs = glob(
                    ["libOTe_Tests/**/*.h"],
                ),
    copts = ["-std=c++14 -O0 -g -ggdb -rdynamic -IlibOTe -maes -msse2 -msse3 -msse4.1 -mpclmul"],
    linkopts = ["-pthread"],
    linkstatic = True,
    deps = [
        ":libOTe",
    ],
)

cc_library(
    name = "lib_frontend_libOTe",
    srcs = glob(["frontend/**/*.cpp"]),
    hdrs = glob(["frontend/**/*.h"]),
    copts = ["-std=c++14 -O0 -g -ggdb -rdynamic -maes -msse2 -msse3 -msse4.1 -mpclmul -DENABLE_CIRCUITS=ON -DENABLE_RELIC=ON -DENABLE_BOOST=ON -DENABLE_SSE=ON"],
    linkopts = ["-pthread -lstdc++"],
    deps = [
                "@ladnir_cryptoTools//:tests_cryptoTools",
                ":libOTe_Tests",
                ":SimplestOT",
    ],
)

cc_binary(
    name = "frontend_libOTe",
    srcs = glob(
                ["frontend/**/*.cpp"],
                ["frontend/**/*.h"],
                ) + ["@ladnir_cryptoTools//:tests_cryptoTools/UnitTests.h"],
    includes = ["./", "@ladnir_cryptoTools/tests_cryptoTools/"],
    copts = ["-I@ladnir_cryptoTools/tests_cryptoTools/ -std=c++14"],
    linkopts = ["-pthread",
            "-L@external/cryptoTools/tests_cryptoTools/",
    ],
    linkstatic = False,
    deps = [
                "@ladnir_cryptoTools//:tests_cryptoTools",
                ":lib_frontend_libOTe",
                ":SimplestOT",
        ],
)
