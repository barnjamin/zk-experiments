from hashlib import sha256
from field import decode_mont


class ShaRng:
    def __init__(self, hashfn):
        self.sha = hashfn

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


def u8_to_u32(u8s: list[int]) -> list[int]:
    elems = 4
    u32s = []
    for idx in range(int(len(u8s) / elems)):
        u32s.append(
            int.from_bytes(bytes(u8s[idx * elems : (idx + 1) * elems]), "little")
        )
    return u32s


def u32_to_u8(u32s: list[int]) -> list[int]:
    u8s = []
    for idx in range(len(u32s)):
        u8s.extend(list(u32s[idx].to_bytes(4, "little")))
    return u8s


class ReadIOP:
    def __init__(self, circuit_outputs: int, seal: list[int]) -> None:
        self.sha = sha256()
        self.proof = seal
        self.rng = ShaRng(self.sha)

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
