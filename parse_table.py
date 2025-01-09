import struct
from abc import ABC
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from typing import Optional, List, BinaryIO

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


def read_varint(file):
    ans = 0
    for i in range(9):
        val = file.read(1)[0]
        if i < 8:
            ans <<= 7
            ans += val & ~0x80
        else:
            ans <<= 8
            ans += val
        if not (val & 0x80):
            break
    return ans


@dataclass
class FileHeader:
    magic_bytes: bytes
    page_size: int
    format_write_version: int
    format_read_version: int
    reserved_bytes: int
    max_embedded_payload_frac: int
    min_embedded_payload_frac: int
    leaf_payload_frac: int
    file_change_counter: int
    file_size_pages: int
    freelist_trunk_ptr: int
    num_freelist_pgs: int
    schema_cookie: int
    schema_format_number: int
    default_page_cache_size: int
    largest_root_b_tree_ptr: int
    text_encoding: str
    user_version: int
    vacuum_mode: bool
    app_id: int
    version_valid_for: int
    sqlite_version_number: int

    def __init__(self, file: BinaryIO):
        (
            self.magic_bytes,
            self.page_size,
            self.format_write_version,
            self.format_read_version,
            self.reserved_bytes,
            self.max_embedded_payload_frac,
            self.min_embedded_payload_frac,
            self.leaf_payload_frac,
            self.file_change_counter,
            self.file_size_pages,
            self.freelist_trunk_ptr,
            self.num_freelist_pgs,
            self.schema_cookie,
            self.schema_format_number,
            self.default_page_cache_size,
            self.largest_root_b_tree_ptr,
            text_encoding,
            self.user_version,
            vacuum_mode,
            self.app_id,
            self.version_valid_for,
            self.sqlite_version_number,
        ) = struct.unpack(">16sH6B12i20x2i", file.read(100))
        self.text_encoding = {
            1: 'utf8',
            2: 'utf16-le',
            3: 'utf16-be'
        }[text_encoding]
        self.vacuum_mode = vacuum_mode != 0


class BTreePageType(Enum):
    TABLE_INTERIOR = 0x05
    TABLE_LEAF = 0x0D
    INDEX_INTERIOR = 0x02
    INDEX_LEAF = 0x10


class TableLeafCell:
    row_id: int
    payload_size: int
    record: "Record"

    def __init__(self, file):
        self.payload_size = read_varint(file)
        self.row_id = read_varint(file)
        self.record = Record(file)


class Record:
    def __init__(self, file: BinaryIO):
        self.values = []
        record_start_offset = file.tell()
        header_size = read_varint(file)
        dtypes = []
        while file.tell() - record_start_offset < header_size:
            dtypes.append(read_varint(file))
        for i, dtype in enumerate(dtypes):
            field_offset = file.tell()
            match dtype:
                case 0:
                    val = None
                case 1:
                    val = file.read(1)[0]
                case 2:
                    val = struct.unpack(">h", file.read(2))[0]
                case 3:
                    # This might go off the end, we'll see if python throws an error...
                    val = struct.unpack(">i", b'\x00' + file.read(3))[0]
                case 4:
                    val = struct.unpack(">i", file.read(4))[0]
                case 5:
                    val = struct.unpack(">q", b'\x00\x00' + file.read(6))
                case 6:
                    val = struct.unpack(">q", file.read(8))
                case 7:
                    # Not sure if this is the right binary IEEE 754 float representation. We'll see...
                    val = struct.unpack(">d", file.read(8))
                case 8:
                    val = 0
                case 9:
                    val = 1
                case x if x >= 12 and x % 2 == 0:  # blob
                    size = (x - 12) // 2
                    val = file.read(size)
                case x if x >= 13 and x % 2 == 1:  # text
                    size = (x - 13) // 2
                    val = file.read(size)
                    val = val.decode('utf-8')  # FIXME: use the text encoding from the file header
                case _:
                    raise ValueError(
                        f"Unexpected dtype: {dtype} at record starting at offset: 0x{record_start_offset:08x}, field: {i} (of {len(dtypes)} fields) at offset: {field_offset:08x}")

            self.values.append(val)


class PageHeader:
    typeId: BTreePageType
    firstFreeBlockOffset: int
    numCellsInPage: int
    cellContentAreaOffset: int
    fragmentedFreeBytes: int
    rightPtr: Optional[int]
    headerSize: int

    def __init__(self, file: BinaryIO):
        self.typeId = BTreePageType(file.read(1)[0])
        (self.firstFreeBlockOffset,
         self.numCellsInPage,
         self.cellContentAreaOffset,
         self.fragmentedFreeBytes) = struct.unpack(">3HB", file.read(7))
        if self.typeId in (BTreePageType.TABLE_INTERIOR, BTreePageType.INDEX_INTERIOR):
            self.rightPtr = struct.unpack_from(">Q", file.read(4))[0]
            self.headerSize = 12
        else:
            self.headerSize = 8


class Page(ABC):
    offset: int
    pageHeader: PageHeader
    cells: List[TableLeafCell]
    def __init__(self):
        self.cells = []

    @property
    def records(self):
        return [cell.record for cell in sorted(self.cells, key=lambda cell: cell.row_id)]


@dataclass
class BTreePage_TableLeaf(Page):
    def __init__(self, file: BinaryIO, page_includes_file_offset: bool = False):
        super().__init__()

        self.offset = file.tell()
        if page_includes_file_offset:
            self.offset -= 100
        self.pageHeader = PageHeader(file)
        num_cells = self.pageHeader.numCellsInPage
        cell_ptrs = struct.unpack(f'>{num_cells}H', file.read(num_cells * 2))
        for ptr in cell_ptrs:
            file.seek(self.offset + ptr)
            self.cells.append(TableLeafCell(file))

class Database:
    def __init__(self, file):
        self.file = file
        self.header = FileHeader(file)
        self.schema_page = BTreePage_TableLeaf(file, True)

def main():
    fname = "./pages/001"
    with open(fname, "rb") as file:
        db = Database(file)
        for record in db.schema_page.records:
            print(record.values)


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


@pytest.mark.parametrize(
    "data, expected_val, expected_delta",
    [
        (b"\x00", 0, 1),
        (b"\x81\x01", 0b10000001, 2),
        (b"\x81\x81\x01", 0b100000010000001, 3),
        (b"\x81" * 8 + b"\x01", 0x0204081020408101, 9),
    ],
)
def test_read_varint(data, expected_val, expected_delta):
    buffer = BytesIO(data)
    buffer.seek(0)
    actual_val = read_varint(buffer)
    assert bin(actual_val) == bin(expected_val)


if __name__ == "__main__":
    main()
