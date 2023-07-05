Target = //:libpsi
Target = //:libpsi_tests
Target = //:psi_test_main

CXX_FLAG = --cxxopt=-std=c++17 
main:
	bazel build --define cpu_arch=x86_64 ${CXX_FLAG} ${Target} 
