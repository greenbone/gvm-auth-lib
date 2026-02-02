![Greenbone Logo](https://www.greenbone.net/wp-content/uploads/gb_new-logo_horizontal_rgb_small.png)

# GVM Authentication Library (gvm-auth-lib) <!-- omit in toc -->

The GVM Authentication Library is a Rust library for common authentication
functionality used within the Greenbone Vulnerability Manager such as
the generation of JSON Web Tokens and communicating with authentication
APIs like OAuth and OpenID Connect.

The library is mostly implemented in Rust but a wrapper for use in C is also
included.
The components are organized as a Rust workspace consisting of multiple crates.

## Main Rust library (gvm-auth-lib)

The `gvm-auth-lib` crate is the main library for use in Rust.

It can be built with the standard Cargo command
```
cargo build -p gvm-auth-lib
```

## C wrapper library (gvm-auth-c-lib)

The `gvm-auth-c-lib` crate is a wrapper of the library for use in C.

It can be built with the standard Cargo command
```
cargo build -p gvm-auth-c-lib
```

### Cgreen tests

To build the Cgreen tests, first create a build directory and initialize the
CMake project inside:
```
mkdir build
cd build
cmake ..
```
Afterwards you can build the tests with the make target `tests` and then run
them with the `test` target:
```
make tests
make test
```

## CLI tools (gvm-auth-cli)

The `gvm-auth-cli` crate is a command line tool for testing various functions
of the GVM authentication libary `gvm-auth-lib`.

It can be built with the standard Cargo command
```
cargo build -p gvm-auth-cli
```
