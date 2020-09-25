These are fuzzing targets for fuzzing [orion](https://github.com/brycx/orion).

Fuzzing is done using [honggfuzz-rs](https://github.com/rust-fuzz/honggfuzz-rs).

### Getting started

To start fuzzing, you must install the same version of honggfuzz as the one  specified in the `Cargo.toml`:

```
cargo install --force honggfuzz --vers 0.5.51
```

By default the master branch of orion is used for fuzzing. If another version needs to be fuzzed, specify the version
in the `Cargo.toml` accordingly.

Some fuzzing targets use [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide) to cross-verify results. Any target 
that uses sodiumoxide requires libsodium to be installed on the system as well.


#### Fuzzing with sanitizers
To fuzz with ASan (with ODR violation detection turned off):

```
RUSTFLAGS="-Z sanitizer=address" ASAN_OPTIONS="detect_odr_violation=0" cargo +nightly hfuzz run aead
```

To fuzz with LeakSanitizer:

```
RUSTFLAGS="-Z sanitizer=leak" cargo +nightly hfuzz run aead
```

Some of the targets do some heavy processing, so specifying the timeout can be required:

```
RUSTFLAGS="-Z sanitizer=address" ASAN_OPTIONS="detect_odr_violation=0" HFUZZ_RUN_ARGS="-t 30" cargo +nightly hfuzz run aead
```

where `-t 30` is in seconds.

All the above examples run the `aead` target. This can be any fuzzing target in `src/` that is not `util`.

#### Corpus minimization

```
HFUZZ_RUN_ARGS="--minimize" cargo hfuzz run aead
```