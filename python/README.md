RISC-0 Receipt Verifier
----------------------

This is a python implementation of a verifier for the [RISC-0](https://www.risczero.com/) Receipt. 

Much of this code was cribbed directly from the [Rust RISC-0 repo](https://github.com/risc0/risc0), Thanks RISC-0 Team!

*WARNING:* This was written for a hackathon, it has not been audited for security.

### TODO:

- document/add comments to explain what is happening
- testing
- standardize encoding/decoding, lots of `to_elem` or `{encode|decode}_mont` in weird spots
- allow other `EXT_SIZE` options
