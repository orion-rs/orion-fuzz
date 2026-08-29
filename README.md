These are fuzzing targets for fuzzing [orion](https://github.com/orion-rs/orion).

Fuzzing is done using [honggfuzz-rs](https://github.com/rust-fuzz/honggfuzz-rs).

### Getting started

To start fuzzing, you must install the same version of honggfuzz as the one  specified in the `Cargo.toml`:

```bash
cargo install --force honggfuzz --vers 0.5.62
```

**Fedora**:
- In case of ZSTD-related errors, make sure `libzstd`, `libzstd-devel` and `libzstd-static` are installed then run with: `LDFLAGS="-lzstd" cargo hfuzz run aead`


By default, the master branch of orion is used for fuzzing. If another version needs to be fuzzed, specify the version
in the `Cargo.toml` accordingly.

Some fuzzing targets use [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide) to cross-verify results. Any target
that uses sodiumoxide requires libsodium to be installed on the system as well.


#### Fuzzing with sanitizers
To fuzz with ASan (with ODR violation detection turned off):

```bash
RUSTFLAGS="-Z sanitizer=address" ASAN_OPTIONS="detect_odr_violation=0" cargo +nightly hfuzz run aead
```

To fuzz with LeakSanitizer:

```bash
RUSTFLAGS="-Z sanitizer=leak" cargo +nightly hfuzz run aead
```

Some of the targets do some heavy processing, so specifying the timeout can be required:

```bash
RUSTFLAGS="-Z sanitizer=address" ASAN_OPTIONS="detect_odr_violation=0" HFUZZ_RUN_ARGS="-t 30" cargo +nightly hfuzz run aead
```

where `-t 30` is in seconds.

All the above examples run the `aead` target. This can be any fuzzing target in `src/` that is not `util`.

#### Corpus minimization

```bash
HFUZZ_RUN_ARGS="--minimize" cargo hfuzz run aead
```

#### Adding seed corpus
This script simply takes any hexstrings found in Orion's `test_data/third_party` (`third_party` because that's where Wycheproof and all the other interesting vectors are), and writes them into respective target input folders.

```bash
python3 ./seed_corpus_from_wycheproof.py orion/tests/test_data/third_party ./hfuzz_workspace
```