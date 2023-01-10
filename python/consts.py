import math

# montgomery form constants
M = int.from_bytes(bytes.fromhex("88000001"), "big")
R2 = 1172168163

# Prime field we're working in
PRIME = int(15 * (1 << 27) + 1)

MIN_CYCLES_PO2 = 10
MIN_CYCLES = 1 << MIN_CYCLES_PO2  # 1k
MAX_CYCLES_PO2 = 24
MAX_CYCLES = 1 << MAX_CYCLES_PO2  # 16M

#  ~100 bits of conjectured security
QUERIES = 50
ZK_CYCLES = QUERIES
MIN_PO2 = math.ceil(math.log2(1 + ZK_CYCLES))

INV_RATE = 4
FRI_FOLD_PO2 = 4
FRI_FOLD = 1 << FRI_FOLD_PO2
FRI_MIN_DEGREE = 256

DIGEST_WORDS = 8
DIGEST_WORD_SIZE = 32

# Extended field element size
EXT_SIZE = 4
CHECK_SIZE = INV_RATE * EXT_SIZE
