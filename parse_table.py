import struct
from dataclasses import dataclass
from enum import Enum

import pytest


def decode_varint(data, offset):
    ans = 0
    i = 0
    while True:
        val = data[offset + i]
        if i < 8:
            ans <<= 7
            ans += val & ~0x80
        else:
            ans <<= 8
            ans += val
        i += 1
        if i == 9 or not (val & 0x80):
            break
    return ans, i


class BTreePageType(Enum):
    TABLE_INTERIOR = 0x05
    TABLE_LEAF = 0x0D
    INDEX_INTERIOR = 0x02
    INDEX_LEAF = 0x10


@dataclass
class BTreeHeader:
    typeId: BTreePageType
    firstFreeBlockOffset: int
    numCellsInPage: int
    cellContentAreaOffset: int
    fragmentedFreeBytes: int
    # rightPtr: int


class TableLeafCell:
    def __init__(self, data, offset):
        self.payload_size, delta = decode_varint(data, offset)
        offset += delta
        self.row_id, delta = decode_varint(data, offset)
        offset += delta
        self.payload = data[offset : offset + self.payload_size - 4 + 1]
        self.record = Record(self)


class Record:
    def __init__(self, cell):
        data = cell.payload
        self.values = []
        header_size, header_offset = decode_varint(data, 0)
        read_offset = header_size
        while header_offset < header_size:
            dtype, delta = decode_varint(data, header_offset)
            header_offset += delta
            match dtype:
                case 0:
                    val = None
                case 1:
                    val = struct.unpack_from(">b", data, offset=read_offset)
                    read_offset += 1
                case 2:
                    val = struct.unpack_from(">h", data, offset=read_offset)
                    read_offset += 2
                case 3:
                    # This might go off the end, we'll see if python throws an error...
                    val = struct.unpack_from(">i", data, offset=read_offset)
                    read_offset += 3
                    val &= 0xFFFFFF
                case 4:
                    val = struct.unpack_from(">i", data, offset=read_offset)
                    read_offset += 4
                case 5:
                    val = struct.unpack_from(">q", data, offset=read_offset)
                    read_offset += 6
                    val &= 0xFFFFFFFFFFFF
                case 6:
                    val = struct.unpack_from(">q", data, offset=read_offset)
                    read_offset += 8
                case 7:
                    val = "FIXME (float)"
                case 8:
                    val = 0
                case 9:
                    val = 1
                case x if x >= 12 and x % 2 == 0:  # blob
                    size = (x - 12) // 2
                    val = data[read_offset : read_offset + size]
                    read_offset += size
                case x if x >= 13 and x % 2 == 1:  # text
                    size = (x - 13) // 2
                    val = data[read_offset : read_offset + size]
                    read_offset += size
                case _:
                    raise ValueError(f"Unexpected dtype: {dtype}")

            self.values.append(val)


def main():
    fname = "./pages/001"
    with open(fname, "rb") as f:
        page_file = f.read()
        header_values = struct.unpack_from(r">BHHHB", page_file, offset=100)
        header = BTreeHeader(*header_values)
        print(header)
        cell_ptr_array = struct.unpack_from(
            f">{header.numCellsInPage}H", page_file, offset=108
        )
        print(f"{cell_ptr_array=}")
        # # cells = [TableLeafCell(page_file, ptr_offset) for ptr_offset in cell_ptr_array]
        # print(cells[3].values)
        cell = TableLeafCell(page_file, cell_ptr_array[0])
        print(cell)
        print(cell.row_id)
        print(cell.record.values)


@pytest.mark.parametrize(
    "data, expected_val, expected_delta",
    [
        (b"\x00", 0, 1),
        (b"\x81\x01", 0b10000001, 2),
        (b"\x81\x81\x01", 0b100000010000001, 3),
        (b"\x81" * 8 + b"\x01", 0x0204081020408101, 9),
    ],
)
def test_decode_varint(data, expected_val, expected_delta):
    actual_val, actual_delta = decode_varint(data, 0)
    assert bin(actual_val) == bin(expected_val)
    assert actual_delta == expected_delta


if __name__ == "__main__":
    main()
