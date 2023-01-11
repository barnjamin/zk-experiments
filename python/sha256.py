"""This Python module is an implementation of the SHA-256 algorithm.
From https://github.com/keanemind/Python-SHA-256"""

K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]

IV = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]


def generate_hash(
    message: bytearray,
    compress_only: bool = False,
    initial_state: list[int] | None = None,
) -> bytearray:
    """Return a SHA-256 hash from the message passed.
    The argument should be a bytes, bytearray, or
    string object."""

    if isinstance(message, str):
        message = bytearray(message, "ascii")
    elif isinstance(message, bytes):
        message = bytearray(message)
    elif not isinstance(message, bytearray):
        raise TypeError

    # Padding
    length = len(message) * 8  # len(message) is number of BYTES!!!
    if not compress_only:
        message.append(0x80)
        while (len(message) * 8 + 64) % 512 != 0:
            message.append(0x00)
        message += length.to_bytes(8, "big")  # pad to 8 bytes or 64 bits

    assert (len(message) * 8) % 512 == 0, "Padding did not complete properly!"

    # Parsing
    blocks = []  # contains 512-bit chunks of message
    for i in range(0, len(message), 64):  # 64 bytes is 512 bits
        blocks.append(message[i : i + 64])

    # Setting Initial Hash Value
    (h0, h1, h2, h3, h4, h5, h6, h7) = IV if initial_state is None else initial_state

    # SHA-256 Hash Computation
    for message_block in blocks:
        # Prepare message schedule
        message_schedule = []
        for t in range(0, 64):
            if t <= 15:
                # adds the t'th 32 bit word of the block,
                # starting from leftmost word
                # 4 bytes at a time
                message_schedule.append(bytes(message_block[t * 4 : (t * 4) + 4]))
            else:
                term1 = _sigma1(int.from_bytes(message_schedule[t - 2], "big"))
                term2 = int.from_bytes(message_schedule[t - 7], "big")
                term3 = _sigma0(int.from_bytes(message_schedule[t - 15], "big"))
                term4 = int.from_bytes(message_schedule[t - 16], "big")

                # append a 4-byte byte object
                schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(
                    4, "big"
                )
                message_schedule.append(schedule)

        assert len(message_schedule) == 64

        # Initialize working variables
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        # Iterate for t=0 to 63
        for t in range(64):
            t1 = (
                h
                + _capsigma1(e)
                + _ch(e, f, g)
                + K[t]
                + int.from_bytes(message_schedule[t], "big")
            ) % 2**32

            t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        # Compute intermediate hash value
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        h5 = (h5 + f) % 2**32
        h6 = (h6 + g) % 2**32
        h7 = (h7 + h) % 2**32

    return (
        (h0).to_bytes(4, "big")  # type: ignore
        + (h1).to_bytes(4, "big")
        + (h2).to_bytes(4, "big")
        + (h3).to_bytes(4, "big")
        + (h4).to_bytes(4, "big")
        + (h5).to_bytes(4, "big")
        + (h6).to_bytes(4, "big")
        + (h7).to_bytes(4, "big")
    )


def _sigma0(num: int):
    """As defined in the specification."""
    num = _rotate_right(num, 7) ^ _rotate_right(num, 18) ^ (num >> 3)
    return num


def _sigma1(num: int):
    """As defined in the specification."""
    num = _rotate_right(num, 17) ^ _rotate_right(num, 19) ^ (num >> 10)
    return num


def _capsigma0(num: int):
    """As defined in the specification."""
    num = _rotate_right(num, 2) ^ _rotate_right(num, 13) ^ _rotate_right(num, 22)
    return num


def _capsigma1(num: int):
    """As defined in the specification."""
    num = _rotate_right(num, 6) ^ _rotate_right(num, 11) ^ _rotate_right(num, 25)
    return num


def _ch(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (~x & z)


def _maj(x: int, y: int, z: int):
    """As defined in the specification."""
    return (x & y) ^ (x & z) ^ (y & z)


def _rotate_right(num: int, shift: int, size: int = 32):
    """Rotate an integer right."""
    return (num >> shift) | (num << size - shift)
