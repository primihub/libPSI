Target = //:libpsi
CXX_FLAG = --cxxopt=-std=c++17 
main:
	bazel build ${Target} ${CXX_FLAG} 
