from hashlib import sha256
from math import log2
from read_iop import ReadIOP
from util import sha_compress


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
        return (i * 2) - self.top_size

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
            top_idx = self.params.idx_to_top(idx)
            self.rest[self.params.idx_to_rest(idx)] = sha_compress(
                self.top[top_idx], self.top[top_idx + 1]
            )

        for idx in range(int(self.params.top_size / 2) - 1, 0, -1):
            upper_rest_idx = self.params.idx_to_rest(idx * 2)
            self.rest[self.params.idx_to_rest(idx)] = sha_compress(
                self.rest[upper_rest_idx], self.rest[upper_rest_idx + 1]
            )

        iop.commit(self.root())

    def root(self):
        return self.rest[self.params.idx_to_rest(1)]

    # def commit_(leafs):
    #    assert len(leafs) & (len(leafs) - 1) == 0, "length must be power of two"
    #    if len(leafs) == 1:
    #        return leafs[0]
    #    else:
    #        return MerkleVerifier.H(
    #            MerkleVerifier.commit_(leafs[: len(leafs) // 2])
    #            + MerkleVerifier.commit_(leafs[len(leafs) // 2 :])
    #        ).digest()

    # def commit(data_array):
    #    return MerkleVerifier.commit_(
    #        [MerkleVerifier.H(bytes(da)).digest() for da in data_array]
    #    )

    # def open_(index, leafs):
    #    assert len(leafs) & (len(leafs) - 1) == 0, "length must be power of two"
    #    assert 0 <= index and index < len(leafs), "cannot open invalid index"
    #    if len(leafs) == 2:
    #        return [leafs[1 - index]]
    #    elif index < (len(leafs) / 2):
    #        return MerkleVerifier.open_(index, leafs[: len(leafs) // 2]) + [
    #            MerkleVerifier.commit_(leafs[len(leafs) // 2 :])
    #        ]
    #    else:
    #        return MerkleVerifier.open_(
    #            index - len(leafs) // 2, leafs[len(leafs) // 2 :]
    #        ) + [MerkleVerifier.commit_(leafs[: len(leafs) // 2])]

    # def open(index, data_array):
    #    return MerkleVerifier.open_(
    #        index, [MerkleVerifier.H(bytes(da)).digest() for da in data_array]
    #    )

    # def verify_(root, index, path, leaf):
    #    assert 0 <= index and index < (1 << len(path)), "cannot verify invalid index"
    #    if len(path) == 1:
    #        if index == 0:
    #            return root == MerkleVerifier.H(leaf + path[0]).digest()
    #        else:
    #            return root == MerkleVerifier.H(path[0] + leaf).digest()
    #    else:
    #        if index % 2 == 0:
    #            return MerkleVerifier.verify_(
    #                root,
    #                index >> 1,
    #                path[1:],
    #                MerkleVerifier.H(leaf + path[0]).digest(),
    #            )
    #        else:
    #            return MerkleVerifier.verify_(
    #                root,
    #                index >> 1,
    #                path[1:],
    #                MerkleVerifier.H(path[0] + leaf).digest(),
    #            )

    # def verify(root, index, path, data_element):
    #    return MerkleVerifier.verify_(
    #        root, index, path, MerkleVerifier.H(bytes(data_element)).digest()
    #    )
