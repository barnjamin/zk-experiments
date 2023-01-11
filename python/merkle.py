from hashlib import sha256
from math import log2
from read_iop import ReadIOP
from fp import Elem
from util import sha_compress_leaves, hash_raw_data


class MerkleParams:

    row_size: int
    col_size: int
    queries: int
    layers: int
    top_layer: int
    top_size: int

    def __init__(self, row_size: int, col_size: int, queries: int) -> None:
        # The number of layers is the logarithm base 2 of the row_size.
        self.queries = queries
        self.row_size = row_size
        self.col_size = col_size

        self.layers: int = int(log2(row_size))
        assert 1 << self.layers == row_size

        # From risc0:
        # The "top" layer is a layer above which we verify all Merkle data only once at
        # the beginning.
        #
        # Later, we only verify merkle branches from the leaf up to this top layer.
        #
        # This allows us to avoid checking hashes in this part of the tree
        # multiple times.
        #
        # We choose the top layer to be the one with size at most equal to queries.

        self.top_layer = 0
        for idx in range(1, self.layers):
            if 1 << idx > queries:
                break
            self.top_layer = idx

        self.top_size = 1 << self.top_layer

    def idx_to_top(self, i: int) -> int:
        return i - self.top_size

    def idx_to_rest(self, i: int) -> int:
        return i - 1


class MerkleVerifier:
    H = sha256

    def __init__(self, iop: ReadIOP, row_size: int, col_size: int, queries: int):
        self.params = MerkleParams(row_size, col_size, queries)

        self.top: list[bytes] = []
        hash_length = 32
        top_raw = iop.read_pod_slice(self.params.top_size * hash_length)
        for idx in range(self.params.top_size):
            self.top.append(bytes(top_raw[idx * hash_length : (idx + 1) * hash_length]))

        self.rest: list[bytes] = [b""] * 32
        self.rest[: len(self.top)] = self.top[:]

        for idx in range(
            self.params.top_size - 1, int(self.params.top_size / 2) - 1, -1
        ):
            top_idx = self.params.idx_to_top(2 * idx)
            self.rest[self.params.idx_to_rest(idx)] = sha_compress_leaves(
                self.top[top_idx], self.top[top_idx + 1]
            )

        for idx in range(int(self.params.top_size / 2) - 1, 0, -1):
            upper_rest_idx = self.params.idx_to_rest(idx * 2)
            self.rest[self.params.idx_to_rest(idx)] = sha_compress_leaves(
                self.rest[upper_rest_idx], self.rest[upper_rest_idx + 1]
            )

        iop.commit(self.root())

    def root(self):
        return self.rest[self.params.idx_to_rest(1)]

    def verify(self, iop: ReadIOP, idx: int) -> list[Elem]:
        if idx >= self.params.row_size:
            raise Exception("no")

        out: list[int] = iop.read_field_elem_slice(self.params.col_size)
        cur: bytes = hash_raw_data(out)

        idx += self.params.row_size

        while idx >= (2 * self.params.top_size):
            # low_bit determines whether hash cur at idx is the left (0) or right (1)
            # child.
            low_bit = idx % 2
            # Retrieve the other parent from the IOP.
            other = bytes(iop.read_pod_slice(32))

            idx //= 2
            if low_bit == 1:
                cur = sha_compress_leaves(other, cur)
            else:
                cur = sha_compress_leaves(cur, other)

        if idx >= self.params.top_size:
            present_hash = self.top[self.params.idx_to_top(idx)]
        else:
            present_hash = self.rest[self.params.idx_to_rest(idx)]

        if present_hash == cur:
            return [Elem(e) for e in out]
        else:
            raise Exception("Invalid Proof")
