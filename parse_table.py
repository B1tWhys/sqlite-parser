import os
import struct
from abc import ABC, abstractmethod
from bisect import bisect_left
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from typing import Optional, List, BinaryIO

import pytest


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
    INDEX_LEAF = 0x0A


class Cell(ABC):
    pass


class TableLeafCell(Cell):
    row_id: int
    payload_size: int
    record: "Record"

    def __init__(self, file):
        self.payload_size = read_varint(file)
        self.row_id = read_varint(file)
        self.record = Record(file)


class TableInteriorCell(Cell):
    child_page_ptr: int
    key: int

    def __init__(self, file: BinaryIO):
        self.child_page_ptr = struct.unpack(">I", file.read(4))[0]
        self.key = read_varint(file)


class IndexInteriorCell(Cell):
    child_page_ptr: int
    payload_size: int
    record: "Record"

    def __init__(self, file: BinaryIO):
        self.child_page_ptr = struct.unpack(">I", file.read(4))[0]
        self.payload_size = read_varint(file)
        self.record = Record(file)


class IndexLeafCell(Cell):
    payload_size: int
    record: "Record"

    def __init__(self, file: BinaryIO):
        self.payload_size = read_varint(file)
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
            self.rightPtr = struct.unpack(">I", file.read(4))[0]
            self.headerSize = 12
        else:
            self.headerSize = 8


class Page(ABC):
    offset: int
    pageHeader: PageHeader
    cells: List[Cell]

    def __init__(self, file: BinaryIO):
        self.offset = file.tell()
        if self.offset <= 100:
            self.offset = 0
        self.cells = []
        self.pageHeader = PageHeader(file)

    @property
    def records(self):
        return [cell.record for cell in sorted(self.cells, key=lambda cell: cell.row_id)]

    @staticmethod
    def build_page(database: "Database", file: BinaryIO):
        page_type = BTreePageType(file.read(1)[0])
        file.seek(-1, os.SEEK_CUR)
        match page_type:
            case BTreePageType.TABLE_LEAF:
                return BTreePage_TableLeaf(file)
            case BTreePageType.TABLE_INTERIOR:
                return BTreePage_TableInterior(file, database)
            case BTreePageType.INDEX_INTERIOR:
                return BTreePage_IndexInterior(file, database)
            case BTreePageType.INDEX_LEAF:
                return BTreePage_IndexLeaf(file, database)
            case _:
                raise ValueError(f"Unsupported page type: {page_type}")

    @abstractmethod
    def get_record(self, key: any) -> Optional[Record]:
        pass


@dataclass
class BTreePage_TableLeaf(Page):
    cells: List[TableLeafCell]

    def __init__(self, file: BinaryIO):
        super().__init__(file)

        num_cells = self.pageHeader.numCellsInPage
        cell_ptrs = struct.unpack(f'>{num_cells}H', file.read(num_cells * 2))
        for ptr in cell_ptrs:
            file.seek(self.offset + ptr)
            self.cells.append(TableLeafCell(file))

    def get_record(self, row_id: int) -> Optional[Record]:
        idx = bisect_left(self.cells, row_id, key=lambda cell: cell.row_id)
        if idx < len(self.cells) and self.cells[idx].row_id == row_id:
            return self.cells[idx].record
        else:
            return None


@dataclass
class BTreePage_TableInterior(Page):
    database: "Database"
    cells: List[TableInteriorCell]

    def __init__(self, file: BinaryIO, database: "Database"):
        super().__init__(file)

        self.database = database
        num_cells = self.pageHeader.numCellsInPage
        cell_ptrs = struct.unpack(f'>{num_cells}H', file.read(num_cells * 2))
        for ptr in cell_ptrs:
            file.seek(self.offset + ptr)
            self.cells.append(TableInteriorCell(file))

    def get_record(self, row_id) -> Optional[Record]:
        idx = bisect_left(self.cells, row_id, key=lambda cell: cell.key)
        if idx < len(self.cells) and self.cells[idx].key >= row_id:
            child_page = self.database.get_page(self.cells[idx].child_page_ptr)
        else:
            child_page = self.database.get_page(self.pageHeader.rightPtr)
        return child_page.get_record(row_id)


@dataclass
class BTreePage_IndexInterior(Page):
    database: "Database"
    cells: List[IndexInteriorCell]

    def __init__(self, file: BinaryIO, db: "Database"):
        super().__init__(file)

        self.database = db
        num_cells = self.pageHeader.numCellsInPage
        cell_ptrs = struct.unpack(f'>{num_cells}H', file.read(num_cells * 2))
        for ptr in cell_ptrs:
            file.seek(self.offset + ptr)
            self.cells.append(IndexInteriorCell(file))

    def get_record(self, key: List[any]) -> Optional[Record]:
        idx = bisect_left(self.cells, key, key=lambda cell: cell.record.values)
        if idx < len(self.cells) and self.cells[idx].record.values >= key:
            child_page = self.database.get_page(self.cells[idx].child_page_ptr)
        else:
            child_page = self.database.get_page(self.pageHeader.rightPtr)
        return child_page.get_record(key)


class BTreePage_IndexLeaf(Page):
    cells: List[IndexLeafCell]

    def __init__(self, file: BinaryIO, db: "Database"):
        super().__init__(file)
        self.database = db
        num_cells = self.pageHeader.numCellsInPage
        cell_ptrs = struct.unpack(f'>{num_cells}H', file.read(num_cells * 2))
        for ptr in cell_ptrs:
            file.seek(self.offset + ptr)
            self.cells.append(IndexLeafCell(file))

    def get_record(self, key: List[any]) -> Optional[Record]:
        idx = bisect_left(self.cells, key, key=lambda cell: cell.record.values)
        if idx >= len(self.cells) or self.cells[idx].record.values[:len(key)] != key:
            return None
        cell_row_id = self.cells[idx].record.values[-1]
        return get_user_info_by_row_id(self.database, cell_row_id)


class Database:
    def __init__(self, file: BinaryIO):
        self.file = file
        self.header = FileHeader(file)
        self.schema_page = self.get_page(1)

    def get_root_page_num(self, target_object_name, target_object_type="table"):
        for record in self.schema_page.records:
            object_type, object_name, object_table, object_page, schema = record.values
            if object_name == target_object_name and object_type == target_object_type:
                return object_page

    def get_page(self, page_number) -> Page:
        page_offset = (page_number - 1) * self.header.page_size
        if page_offset == 0:
            page_offset += 100
        self.file.seek(page_offset)
        return Page.build_page(self, self.file)


def get_user_info_by_row_id(db, row_id, quiet=True) -> List[any] | None:
    users_table_page_num = db.get_root_page_num("users")
    users_table_root = db.get_page(users_table_page_num)
    record = users_table_root.get_record(row_id)
    if record is None:
        if not quiet: print("Didn't find the record!")
        return None
    else:
        if not quiet: print(record.values)
        return record


def get_user_info_by_email(db, email):
    col_name_to_index_name = {
        "username": "sqlite_autoindex_users_1",
        "email": "sqlite_autoindex_users_2"
    }
    page_num = db.get_root_page_num("sqlite_autoindex_users_2", "index")
    root_page = db.get_page(page_num)
    cell: IndexInteriorCell = root_page.cells[0]
    # print(cell.record.values)
    # print(cell.child_page_ptr)
    record = root_page.get_record([email])
    if record is None:
        print(f"Didn't find email: {email}")
    else:
        print(record.values)
        return record


def main():
    fname = "./example.db"
    TARGET_ROW_ID = 450  # "450|user_450|user_450@example.com|password_450|2025-01-02 05:44:00"
    # TARGET_EMAIL_ID = "user_450@example.com"
    TARGET_EMAIL_ID = "asdf"
    with open(fname, "rb") as file:
        db = Database(file)
        # get_user_info_by_row_id(db, TARGET_ROW_ID)
        get_user_info_by_email(db, TARGET_EMAIL_ID)


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
