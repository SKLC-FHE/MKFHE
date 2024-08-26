# MK-FHE
 
A proof of concept for NTRU based MKFHE
=====================================

### Requirements

OpenFHE v1.1.1, 

a C++ compiler, the NTL, GMP libraries.

## Run the code

1. Configure, build and compile the project.

```
mkdir build
cd build
cmake -DWITH_NTL=ON  -DNATIVE_SIZE=32 -DWITH_NATIVEOPT=ON -DCMAKE_C_COMPILER=clang-12 -DCMAKE_CXX_COMPILER=clang++-12 -DWITH_OPENMP=OFF -DCMAKE_C_FLAGS="-pthread" -DCMAKE_CXX_FLAGS="-pthread" ..
make 
```

2. Run the `boolean-ntru` or `boolean-lwe` program in `build/bin/examples/binfhe`

