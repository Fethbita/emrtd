# Rust eMRTD

## Introduction

A library that can read an eMRTD (Electronic Machine Readable Travel Document).

The `emrtd` crate provides a simple API that can be used to communicate with
eMRTDs and read the data that resides within them. With the help of openssl,
it can perform Passive Authentication.

**NOTE:**
Please note that this crate is provided 'as is' and is not considered production-ready. Use at your own risk.

**WARNING:**
Currently Active Authentication (AA), Chip Authentication (CA), PACE or EAC are **not** supported.

## License

Licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
