from hashlib import sha256
from math import log2



# /// A struct against which we verify merkle branches, consisting of the
# /// parameters of the Merkle tree and top - the vector of hash values in the top
# /// row of the tree, above which we verify only once.
# pub struct MerkleTreeVerifier<'a, H: VerifyHal> {
#     params: MerkleTreeParams,
# 
#     // Conceptually, the merkle tree here is twice as long as the
#     // "top" row (params.top_size), minus element #0.  The children of
#     // the entry at virtual index i are stored at 2*i and 2*i+1.  The
#     // root of the tree is at virtual element #1.
# 
#     // "top" is a reference, top_size long, to the top row.  This
#     // contains the virtual indexes [top_size..top_size*2).
#     top: &'a [Digest],
# 
#     // These are the rest of the tree.  These have the virtual indexes [1, top_size).
#     rest: Vec<<H::Sha as Sha>::DigestPtr>,
# 
#     // Support for accelerator operations.
#     hal: &'a H,
# }

class MerkleParams:

    row_size: int
    col_size: int
    queries: int
    layers: int
    top_layer: int
    top_size: int

    def __init__(self, row_size: int, col_size: int, queries: int) -> None:
        # The number of layers is the logarithm base 2 of the row_size.
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

        top_layer = 0
        # for i in 1..layers {
        #     if (1 << i) > queries {
        #         break;
        #     }
        #     top_layer = i;
        # }
        # let top_size = 1 << top_layer;
        # MerkleTreeParams {
        #     row_size,
        #     col_size,
        #     queries,
        #     layers,
        #     top_layer,
        #     top_size,
        # }
        pass

class MerkleVerifier:
    H = sha256

    def commit_(leafs):
        assert len(leafs) & (len(leafs) - 1) == 0, "length must be power of two"
        if len(leafs) == 1:
            return leafs[0]
        else:
            return MerkleVerifier.H(
                MerkleVerifier.commit_(leafs[: len(leafs) // 2])
                + MerkleVerifier.commit_(leafs[len(leafs) // 2 :])
            ).digest()

    def commit(data_array):
        return MerkleVerifier.commit_(
            [MerkleVerifier.H(bytes(da)).digest() for da in data_array]
        )

    def open_(index, leafs):
        assert len(leafs) & (len(leafs) - 1) == 0, "length must be power of two"
        assert 0 <= index and index < len(leafs), "cannot open invalid index"
        if len(leafs) == 2:
            return [leafs[1 - index]]
        elif index < (len(leafs) / 2):
            return MerkleVerifier.open_(index, leafs[: len(leafs) // 2]) + [
                MerkleVerifier.commit_(leafs[len(leafs) // 2 :])
            ]
        else:
            return MerkleVerifier.open_(
                index - len(leafs) // 2, leafs[len(leafs) // 2 :]
            ) + [MerkleVerifier.commit_(leafs[: len(leafs) // 2])]

    def open(index, data_array):
        return MerkleVerifier.open_(
            index, [MerkleVerifier.H(bytes(da)).digest() for da in data_array]
        )

    def verify_(root, index, path, leaf):
        assert 0 <= index and index < (1 << len(path)), "cannot verify invalid index"
        if len(path) == 1:
            if index == 0:
                return root == MerkleVerifier.H(leaf + path[0]).digest()
            else:
                return root == MerkleVerifier.H(path[0] + leaf).digest()
        else:
            if index % 2 == 0:
                return MerkleVerifier.verify_(
                    root,
                    index >> 1,
                    path[1:],
                    MerkleVerifier.H(leaf + path[0]).digest(),
                )
            else:
                return MerkleVerifier.verify_(
                    root,
                    index >> 1,
                    path[1:],
                    MerkleVerifier.H(path[0] + leaf).digest(),
                )

    def verify(root, index, path, data_element):
        return MerkleVerifier.verify_(
            root, index, path, MerkleVerifier.H(bytes(data_element)).digest()
        )
