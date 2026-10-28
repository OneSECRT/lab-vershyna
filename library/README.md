# DSTU 9212 Reference Implementation

Reference implementation of DSTU 9212 in C.

The implementation includes:

- DSTU 9212 parameters, polynomial arithmetic, conversions, key generation,
  digital signature generation, and digital signature verification.
- DSTU 7564 "Kupyna" hash implementation adapted for DSTU 9212 hash
  primitives.
- DSTU 8845 "Strumok" stream cipher implementation adapted for DSTU 9212 PRNG
  primitives.
- Test vectors and conformance tests for all supported parameter sets.
- A small high-level API that uses the system randomness source.

## Layout

```text
include/dstu9212/       Public DSTU 9212 headers
src/                    DSTU 9212 implementation sources
third_party/dstu7564/   DSTU 7564 dependency
third_party/dstu8845/   DSTU 8845 dependency
examples/               API usage examples
tests/                  Unit and test-vector checks
test_vectors/           Checked-in test vectors
tools/                  Developer tools
```

## Build

Build the static library and the example program:

```sh
make
```

Run the example:

```sh
make run
```

Run tests for the default mode:

```sh
make test
```

Run tests for all supported modes:

```sh
make MODE=1 test
make MODE=2 test
make MODE=3 test
make MODE=4 test
```

Run the portable wall-clock benchmark (ten iterations by default):

```sh
make MODE=1 benchmark
make MODE=1 benchmark BENCHMARK_ITERATIONS=100
```

Generate test vectors:

```sh
make generate-test-vectors
```

or write to a custom path:

```sh
make generate-test-vectors TEST_VECTORS_OUTPUT=/tmp/dstu9212_vectors.txt
```

## Public API

Applications should include the umbrella header:

```c
#include <dstu9212/dstu9212.h>
```

The high-level API is declared in `include/dstu9212/api.h`.

## Security and constant-time scope

The portable polynomial, NTT, rounding, packing, norm-checking, comparison,
and secret-erasure code is written without secret-dependent division or early
exit. Signing still uses the rejection-sampling structure required by DSTU
9212; as in CRYSTALS-Dilithium, its number of iterations is variable.

There is one explicit constant-time exception: the bundled DSTU 7564
(`Kupyna`) and DSTU 8845 (`Strumok`) implementations use secret-indexed
T-tables. On CPUs with data caches this can expose cache-timing information
when hashing secret signing material or generating a secret-dependent stream.
Consequently, this implementation as a whole must **not** be described as
fully constant-time and should not be deployed where an attacker can measure
fine-grained timing or shared-cache effects. Replacing both primitives with
audited bitsliced or otherwise cache-constant backends is required to remove
this exception.

The implementation has not yet undergone an independent security audit.

## Portable implementation notes

The optimization and hardening baseline is the portable `ref` implementation
from [pq-crystals/dilithium](https://github.com/pq-crystals/dilithium), reviewed
at commit `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be`. The algorithms were adapted to
DSTU 9212 parameter sets, including the 512-coefficient modes and the mandated
Kupyna/Strumok primitives. In particular, this implementation now uses:

- fixed-step pseudo-Mersenne and Montgomery reduction instead of integer
  division in polynomial and NTT paths;
- precomputed Montgomery NTT roots, branchless modular butterflies, and
  bounded branchless add/sub reduction;
- reciprocal-based power-of-two rounding, decomposition, and eta-2 sampling;
- word-buffered packing/unpacking with full-input validation;
- contiguous workspaces instead of many per-operation allocations;
- full-vector norm checks, the upstream `(Q - 1) / 8` bound check, constant-time
  final challenge comparison, and non-elidable secret erasure; and
- alignment-safe, endian-explicit Kupyna input/output handling and reentrant
  automatic scratch storage in both bundled primitives.

Use `make MODE=<1..4> benchmark` for local measurements. Benchmark results are
machine- and workload-dependent, especially because signing uses rejection
sampling.

## Modes

The selected mode is controlled at compile time through `DSTU9212_MODE`.
The Makefile accepts:

- `MODE=1` for Vershyna 128/64
- `MODE=2` for Vershyna 256/128
- `MODE=3` for Vershyna 384/192
- `MODE=4` for Vershyna 512/256

## License

This project is licensed under the Apache License 2.0. See `LICENSE` for the
full license text.
