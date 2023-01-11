from consts import MIN_CYCLES_PO2


class Method:
    def __init__(self, table: list[bytes]):
        self.table = table

    @staticmethod
    def from_bytes(raw: bytes) -> "Method":
        chunk_size = 32
        table: list[bytes] = []
        for idx in range(int(len(raw) / chunk_size)):
            word = list(raw[idx * chunk_size : (idx + 1) * chunk_size])
            table.append(bytes(word))
        return Method(table)


def check_code_merkle(po2: int, method: Method, merkle_root: bytes) -> bool:
    which = po2 - MIN_CYCLES_PO2
    assert which < len(method.table), "Method cycle error"
    assert method.table[which] == merkle_root, "Verify error"
    return True
