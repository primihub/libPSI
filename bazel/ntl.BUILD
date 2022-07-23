package(default_visibility = ["//visibility:public",],)

# https://khjtony.github.io/programming/2018/12/31/Add-external-library-to-bazel.html

include_files = [
    "includes/NTL/ALL_FEATURES.h",
    "includes/NTL/BasicThreadPool.h",
    "includes/NTL/FFT.h",
    "includes/NTL/FFT_impl.h",
    "includes/NTL/FacVec.h",
    "includes/NTL/GF2.h",
    "includes/NTL/GF2E.h",
    "includes/NTL/GF2EX.h",
    "includes/NTL/GF2EXFactoring.h",
    "includes/NTL/GF2X.h",
    "includes/NTL/GF2XFactoring.h",
    "includes/NTL/GF2XVec.h",
    "includes/NTL/HNF.h",
    "includes/NTL/LLL.h",
    "includes/NTL/Lazy.h",
    "includes/NTL/LazyTable.h",
    "includes/NTL/MatPrime.h",
    "includes/NTL/PD.h",
    "includes/NTL/PackageInfo.h",
    "includes/NTL/REPORT_ALL_FEATURES.h",
    "includes/NTL/RR.h",
    "includes/NTL/SmartPtr.h",
    "includes/NTL/WordVector.h",
    "includes/NTL/ZZ.h",
    "includes/NTL/ZZVec.h",
    "includes/NTL/ZZX.h",
    "includes/NTL/ZZXFactoring.h",
    "includes/NTL/ZZ_limbs.h",
    "includes/NTL/ZZ_p.h",
    "includes/NTL/ZZ_pE.h",
    "includes/NTL/ZZ_pEX.h",
    "includes/NTL/ZZ_pEXFactoring.h",
    "includes/NTL/ZZ_pX.h",
    "includes/NTL/ZZ_pXFactoring.h",
    "includes/NTL/ctools.h",
    "includes/NTL/fileio.h",
    "includes/NTL/linux_s390x.h",
    "includes/NTL/lip.h",
    "includes/NTL/lzz_p.h",
    "includes/NTL/lzz_pE.h",
    "includes/NTL/lzz_pEX.h",
    "includes/NTL/lzz_pEXFactoring.h",
    "includes/NTL/lzz_pX.h",
    "includes/NTL/lzz_pXFactoring.h",
    "includes/NTL/mat_GF2.h",
    "includes/NTL/mat_GF2E.h",
    "includes/NTL/mat_RR.h",
    "includes/NTL/mat_ZZ.h",
    "includes/NTL/mat_ZZ_p.h",
    "includes/NTL/mat_ZZ_pE.h",
    "includes/NTL/mat_lzz_p.h",
    "includes/NTL/mat_lzz_pE.h",
    "includes/NTL/mat_poly_ZZ.h",
    "includes/NTL/mat_poly_ZZ_p.h",
    "includes/NTL/mat_poly_lzz_p.h",
    "includes/NTL/matrix.h",
    "includes/NTL/new.h",
    "includes/NTL/pair.h",
    "includes/NTL/pair_GF2EX_long.h",
    "includes/NTL/pair_GF2X_long.h",
    "includes/NTL/pair_ZZX_long.h",
    "includes/NTL/pair_ZZ_pEX_long.h",
    "includes/NTL/pair_ZZ_pX_long.h",
    "includes/NTL/pair_lzz_pEX_long.h",
    "includes/NTL/pair_lzz_pX_long.h",
    "includes/NTL/pd_FFT.h",
    "includes/NTL/quad_float.h",
    "includes/NTL/sp_arith.h",
    "includes/NTL/thread.h",
    "includes/NTL/tools.h",
    "includes/NTL/vec_GF2.h",
    "includes/NTL/vec_GF2E.h",
    "includes/NTL/vec_GF2XVec.h",
    "includes/NTL/vec_RR.h",
    "includes/NTL/vec_ZZ.h",
    "includes/NTL/vec_ZZVec.h",
    "includes/NTL/vec_ZZ_p.h",
    "includes/NTL/vec_ZZ_pE.h",
    "includes/NTL/vec_double.h",
    "includes/NTL/vec_long.h",
    "includes/NTL/vec_lzz_p.h",
    "includes/NTL/vec_lzz_pE.h",
    "includes/NTL/vec_quad_float.h",
    "includes/NTL/vec_ulong.h",
    "includes/NTL/vec_vec_GF2.h",
    "includes/NTL/vec_vec_GF2E.h",
    "includes/NTL/vec_vec_RR.h",
    "includes/NTL/vec_vec_ZZ.h",
    "includes/NTL/vec_vec_ZZ_p.h",
    "includes/NTL/vec_vec_ZZ_pE.h",
    "includes/NTL/vec_vec_long.h",
    "includes/NTL/vec_vec_lzz_p.h",
    "includes/NTL/vec_vec_lzz_pE.h",
    "includes/NTL/vec_vec_ulong.h",
    "includes/NTL/vec_xdouble.h",
    "includes/NTL/vector.h",
    "includes/NTL/version.h",
    "includes/NTL/xdouble.h",
]

lib_files = [
    "lib/libntl.a",
]

genrule(
    name = "libntl-build",
    srcs = glob(["**"], exclude=["bazel-*"]),
    outs = include_files + lib_files,
    cmd = """
        set -x
        NTL_ROOT=$$(dirname $(location src/configure))
        pushd $$NTL_ROOT
            ./configure PREFIX=/tmp NTL_THREADS=on NTL_THREAD_BOOST=on NTL_EXCEPTIONS=on SHARED=on NTL_STD_CXX11=on NTL_SAFE_VECTORS=off TUNE=generic
            make && make install
        popd
        cp /tmp/lib/libntl.a $(location lib/libntl.a)
        cp /tmp/include/NTL/ALL_FEATURES.h             $(location includes/NTL/ALL_FEATURES.h)
        cp /tmp/include/NTL/BasicThreadPool.h          $(location includes/NTL/BasicThreadPool.h)
        cp /tmp/include/NTL/FFT.h                      $(location includes/NTL/FFT.h)
        cp /tmp/include/NTL/FFT_impl.h                 $(location includes/NTL/FFT_impl.h)
        cp /tmp/include/NTL/FacVec.h                   $(location includes/NTL/FacVec.h)
        cp /tmp/include/NTL/GF2.h                      $(location includes/NTL/GF2.h)
        cp /tmp/include/NTL/GF2E.h                     $(location includes/NTL/GF2E.h)
        cp /tmp/include/NTL/GF2EX.h                    $(location includes/NTL/GF2EX.h)
        cp /tmp/include/NTL/GF2EXFactoring.h           $(location includes/NTL/GF2EXFactoring.h)
        cp /tmp/include/NTL/GF2X.h                     $(location includes/NTL/GF2X.h)
        cp /tmp/include/NTL/GF2XFactoring.h            $(location includes/NTL/GF2XFactoring.h)
        cp /tmp/include/NTL/GF2XVec.h                  $(location includes/NTL/GF2XVec.h)
        cp /tmp/include/NTL/HNF.h                      $(location includes/NTL/HNF.h)
        cp /tmp/include/NTL/LLL.h                      $(location includes/NTL/LLL.h)
        cp /tmp/include/NTL/Lazy.h                     $(location includes/NTL/Lazy.h)
        cp /tmp/include/NTL/LazyTable.h                $(location includes/NTL/LazyTable.h)
        cp /tmp/include/NTL/MatPrime.h                 $(location includes/NTL/MatPrime.h)
        cp /tmp/include/NTL/PD.h                       $(location includes/NTL/PD.h)
        cp /tmp/include/NTL/PackageInfo.h              $(location includes/NTL/PackageInfo.h)
        cp /tmp/include/NTL/REPORT_ALL_FEATURES.h      $(location includes/NTL/REPORT_ALL_FEATURES.h)
        cp /tmp/include/NTL/RR.h                       $(location includes/NTL/RR.h)
        cp /tmp/include/NTL/SmartPtr.h                 $(location includes/NTL/SmartPtr.h)
        cp /tmp/include/NTL/WordVector.h               $(location includes/NTL/WordVector.h)
        cp /tmp/include/NTL/ZZ.h                       $(location includes/NTL/ZZ.h)
        cp /tmp/include/NTL/ZZVec.h                    $(location includes/NTL/ZZVec.h)
        cp /tmp/include/NTL/ZZX.h                      $(location includes/NTL/ZZX.h)
        cp /tmp/include/NTL/ZZXFactoring.h             $(location includes/NTL/ZZXFactoring.h)
        cp /tmp/include/NTL/ZZ_limbs.h                 $(location includes/NTL/ZZ_limbs.h)
        cp /tmp/include/NTL/ZZ_p.h                     $(location includes/NTL/ZZ_p.h)
        cp /tmp/include/NTL/ZZ_pE.h                    $(location includes/NTL/ZZ_pE.h)
        cp /tmp/include/NTL/ZZ_pEX.h                   $(location includes/NTL/ZZ_pEX.h)
        cp /tmp/include/NTL/ZZ_pEXFactoring.h          $(location includes/NTL/ZZ_pEXFactoring.h)
        cp /tmp/include/NTL/ZZ_pX.h                    $(location includes/NTL/ZZ_pX.h)
        cp /tmp/include/NTL/ZZ_pXFactoring.h           $(location includes/NTL/ZZ_pXFactoring.h)
        cp /tmp/include/NTL/ctools.h                   $(location includes/NTL/ctools.h)
        cp /tmp/include/NTL/fileio.h                   $(location includes/NTL/fileio.h)
        cp /tmp/include/NTL/linux_s390x.h              $(location includes/NTL/linux_s390x.h)
        cp /tmp/include/NTL/lip.h                      $(location includes/NTL/lip.h)
        cp /tmp/include/NTL/lzz_p.h                    $(location includes/NTL/lzz_p.h)
        cp /tmp/include/NTL/lzz_pE.h                   $(location includes/NTL/lzz_pE.h)
        cp /tmp/include/NTL/lzz_pEX.h                  $(location includes/NTL/lzz_pEX.h)
        cp /tmp/include/NTL/lzz_pEXFactoring.h         $(location includes/NTL/lzz_pEXFactoring.h)
        cp /tmp/include/NTL/lzz_pX.h                   $(location includes/NTL/lzz_pX.h)
        cp /tmp/include/NTL/lzz_pXFactoring.h          $(location includes/NTL/lzz_pXFactoring.h)
        cp /tmp/include/NTL/mat_GF2.h                  $(location includes/NTL/mat_GF2.h)
        cp /tmp/include/NTL/mat_GF2E.h                 $(location includes/NTL/mat_GF2E.h)
        cp /tmp/include/NTL/mat_RR.h                   $(location includes/NTL/mat_RR.h)
        cp /tmp/include/NTL/mat_ZZ.h                   $(location includes/NTL/mat_ZZ.h)
        cp /tmp/include/NTL/mat_ZZ_p.h                 $(location includes/NTL/mat_ZZ_p.h)
        cp /tmp/include/NTL/mat_ZZ_pE.h                $(location includes/NTL/mat_ZZ_pE.h)
        cp /tmp/include/NTL/mat_lzz_p.h                $(location includes/NTL/mat_lzz_p.h)
        cp /tmp/include/NTL/mat_lzz_pE.h               $(location includes/NTL/mat_lzz_pE.h)
        cp /tmp/include/NTL/mat_poly_ZZ.h              $(location includes/NTL/mat_poly_ZZ.h)
        cp /tmp/include/NTL/mat_poly_ZZ_p.h            $(location includes/NTL/mat_poly_ZZ_p.h)
        cp /tmp/include/NTL/mat_poly_lzz_p.h           $(location includes/NTL/mat_poly_lzz_p.h)
        cp /tmp/include/NTL/matrix.h                   $(location includes/NTL/matrix.h)
        cp /tmp/include/NTL/new.h                      $(location includes/NTL/new.h)
        cp /tmp/include/NTL/pair.h                     $(location includes/NTL/pair.h)
        cp /tmp/include/NTL/pair_GF2EX_long.h          $(location includes/NTL/pair_GF2EX_long.h)
        cp /tmp/include/NTL/pair_GF2X_long.h           $(location includes/NTL/pair_GF2X_long.h)
        cp /tmp/include/NTL/pair_ZZX_long.h            $(location includes/NTL/pair_ZZX_long.h)
        cp /tmp/include/NTL/pair_ZZ_pEX_long.h         $(location includes/NTL/pair_ZZ_pEX_long.h)
        cp /tmp/include/NTL/pair_ZZ_pX_long.h          $(location includes/NTL/pair_ZZ_pX_long.h)
        cp /tmp/include/NTL/pair_lzz_pEX_long.h        $(location includes/NTL/pair_lzz_pEX_long.h)
        cp /tmp/include/NTL/pair_lzz_pX_long.h         $(location includes/NTL/pair_lzz_pX_long.h)
        cp /tmp/include/NTL/pd_FFT.h                   $(location includes/NTL/pd_FFT.h)
        cp /tmp/include/NTL/quad_float.h               $(location includes/NTL/quad_float.h)
        cp /tmp/include/NTL/sp_arith.h                 $(location includes/NTL/sp_arith.h)
        cp /tmp/include/NTL/thread.h                   $(location includes/NTL/thread.h)
        cp /tmp/include/NTL/tools.h                    $(location includes/NTL/tools.h)
        cp /tmp/include/NTL/vec_GF2.h                  $(location includes/NTL/vec_GF2.h)
        cp /tmp/include/NTL/vec_GF2E.h                 $(location includes/NTL/vec_GF2E.h)
        cp /tmp/include/NTL/vec_GF2XVec.h              $(location includes/NTL/vec_GF2XVec.h)
        cp /tmp/include/NTL/vec_RR.h                   $(location includes/NTL/vec_RR.h)
        cp /tmp/include/NTL/vec_ZZ.h                   $(location includes/NTL/vec_ZZ.h)
        cp /tmp/include/NTL/vec_ZZVec.h                $(location includes/NTL/vec_ZZVec.h)
        cp /tmp/include/NTL/vec_ZZ_p.h                 $(location includes/NTL/vec_ZZ_p.h)
        cp /tmp/include/NTL/vec_ZZ_pE.h                $(location includes/NTL/vec_ZZ_pE.h)
        cp /tmp/include/NTL/vec_double.h               $(location includes/NTL/vec_double.h)
        cp /tmp/include/NTL/vec_long.h                 $(location includes/NTL/vec_long.h)
        cp /tmp/include/NTL/vec_lzz_p.h                $(location includes/NTL/vec_lzz_p.h)
        cp /tmp/include/NTL/vec_lzz_pE.h               $(location includes/NTL/vec_lzz_pE.h)
        cp /tmp/include/NTL/vec_quad_float.h           $(location includes/NTL/vec_quad_float.h)
        cp /tmp/include/NTL/vec_ulong.h                $(location includes/NTL/vec_ulong.h)
        cp /tmp/include/NTL/vec_vec_GF2.h              $(location includes/NTL/vec_vec_GF2.h)
        cp /tmp/include/NTL/vec_vec_GF2E.h             $(location includes/NTL/vec_vec_GF2E.h)
        cp /tmp/include/NTL/vec_vec_RR.h               $(location includes/NTL/vec_vec_RR.h)
        cp /tmp/include/NTL/vec_vec_ZZ.h               $(location includes/NTL/vec_vec_ZZ.h)
        cp /tmp/include/NTL/vec_vec_ZZ_p.h             $(location includes/NTL/vec_vec_ZZ_p.h)
        cp /tmp/include/NTL/vec_vec_ZZ_pE.h            $(location includes/NTL/vec_vec_ZZ_pE.h)
        cp /tmp/include/NTL/vec_vec_long.h             $(location includes/NTL/vec_vec_long.h)
        cp /tmp/include/NTL/vec_vec_lzz_p.h            $(location includes/NTL/vec_vec_lzz_p.h)
        cp /tmp/include/NTL/vec_vec_lzz_pE.h           $(location includes/NTL/vec_vec_lzz_pE.h)
        cp /tmp/include/NTL/vec_vec_ulong.h            $(location includes/NTL/vec_vec_ulong.h)
        cp /tmp/include/NTL/vec_xdouble.h              $(location includes/NTL/vec_xdouble.h)
        cp /tmp/include/NTL/vector.h                   $(location includes/NTL/vector.h)
        cp /tmp/include/NTL/version.h                  $(location includes/NTL/version.h)
        cp /tmp/include/NTL/xdouble.h                  $(location includes/NTL/xdouble.h)      
    """,
)

cc_library(
    name = "libntl",
    srcs = lib_files,
    hdrs = include_files,
    includes=["includes"],
    linkstatic = 1,
)
