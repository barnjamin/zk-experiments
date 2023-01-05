from typing import Callable
from hashlib import sha256, _Hash

# impl<S: Sha> RngCore for ShaRng<S> {
#     fn next_u32(&mut self) -> u32 {
#         if self.pool_used == DIGEST_WORDS {
#             self.step();
#         }
#         let out = self.pool0.get()[self.pool_used];
#         // Mark this word as used.
#         self.pool_used += 1;
#         out
#     }
#
#     fn next_u64(&mut self) -> u64 {
#         ((self.next_u32() as u64) << 32) | (self.next_u32() as u64)
#     }
#
#     fn fill_bytes(&mut self, dest: &mut [u8]) {
#         impls::fill_bytes_via_next(self, dest);
#     }
#
#     fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
#         Ok(self.fill_bytes(dest))
#     }
# }

WORDS = 1


class FieldElement:
    @staticmethod
    def from_u32s(words: list[int]) -> "FieldElement":
        return FieldElement()


class ShaRng:
    def __init__(self, hashfn: Callable[..., _Hash]):
        self.sha = hashfn()

        self.sha.update(b"Hello")
        self.pool0 = self.sha.digest()

        self.sha.update(b"World")
        self.pool1 = self.sha.digest()

        self.pool_used = 0

    def mix(self, digest: bytes):
        # // Generate a new digest by mixing two digests together via XOR,
        # // and stores it back in the pool.
        # fn mix(&self, pool: &mut Self::DigestPtr, val: &Digest) {
        #     // CPU based sha can do this in place without generating another digest pointer.
        #     for (pool_word, val_word) in pool.get_mut().iter_mut().zip(val.get()) {
        #         *pool_word ^= *val_word;
        #     }
        # }
        pass

    def step(self):
        # self.pool0 = self.sha.hash_pair(&self.pool0, &self.pool1);
        # self.pool1 = self.sha.hash_pair(&self.pool0, &self.pool1);
        # self.pool_used = 0;
        pass


class ReadIOP:
    def __init__(self, seal: list[int]) -> None:
        self.sha: _Hash = sha256()
        self.proof = seal
        self.rng = ShaRng(self.sha)

    def read_u32s(self, size: int) -> list[int]:
        u32s = self.proof[:size]
        self.proof = self.proof[:size]
        return u32s

    def read_field_elem_slice(self, size: int) -> list[int]:
        self.read_u32s(size * WORDS)

    def read_pod_slice(self, size: int) -> list[int]:
        u32s = self.proof[:size]
        self.proof = self.proof[:size]
        return u32s

    def commit(self, digest: bytes) -> None:
        self.rng.mix(digest)

    def verify_complete(self):
        assert len(self.proof) == 0
