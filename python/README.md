RISC-0 Receipt Verifier
----------------------

This is a python implementation of a verifier for the RISC-0 receipt. 

*WARNING:* This was written for a hackathon, it has not been audited for security.

A lot of this code was ripped from the [Rust RISC-0 repo](https://github.com/risc0/risc0) 

TODO:
    license? credit original risc0 authors better
    document/add comments to explain what is happening
    testing
    standardize encoding/decoding, lots of `to_elem` or `{encode|decode}_mont` in weird spots
    allow other `EXT_SIZE` options
