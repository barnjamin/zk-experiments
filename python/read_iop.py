from util import sha_compress, u32_to_u8, u8_to_u32, sha_hash, decode_mont
from consts import DIGEST_WORDS


class ShaRng:
    def __init__(self):
        self.pool0 = sha_hash(b"Hello")
        self.pool1 = sha_hash(b"World")
        self.pool_used = 0

    def mix(self, digest: bytes):
        # Generate a new digest by mixing two digests together via XOR,
        # and stores it back in the pool.
        pool_words = u8_to_u32(list(self.pool0))
        val = u8_to_u32(list(digest))

        mixed = []
        for idx in range(len(pool_words)):
            pool_word = pool_words[idx]
            val_word = val[idx]
            mixed.append(pool_word ^ val_word)

        self.pool0 = u32_to_u8(mixed)
        self.step()

    def step(self):
        self.pool0 = sha_compress(self.pool0, self.pool1)
        self.pool1 = sha_compress(self.pool0, self.pool1)
        self.pool_used = 0

    def next_u32(self) -> int:
        if self.pool_used == DIGEST_WORDS:
            self.step()

        as_words = u8_to_u32(self.pool0)
        out = as_words[self.pool_used]
        self.pool_used += 1
        return out


class ReadIOP:
    def __init__(self, circuit_outputs: int, seal: list[int]) -> None:
        self.proof = seal
        self.rng = ShaRng()

        self.out = self.read_field_elem_slice(circuit_outputs)
        self.po2 = self.read_u32s(1).pop()

    def read_u32s(self, size: int) -> list[int]:
        u32s = u8_to_u32(self.proof[: size * 4])
        self.proof = self.proof[size * 4 :]
        return u32s

    def read_field_elem_slice(self, size: int) -> list[int]:
        elems = []
        for u in self.read_u32s(size):
            elems.append(decode_mont(u))
        return elems

    def read_pod_slice(self, size: int) -> list[int]:
        b = self.proof[:size]
        self.proof = self.proof[size:]
        return b

    def commit(self, digest: bytes) -> None:
        self.rng.mix(digest)

    def verify_complete(self):
        assert len(self.proof) == 0
