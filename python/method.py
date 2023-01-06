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
