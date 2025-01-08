from pathlib import Path

PAGE_SIZE = 4096
input_path = Path("./example.db")
output_path = Path("./pages")

output_path.mkdir(exist_ok=True)

i = 1  # pages are 1-indexed
with input_path.open("rb") as raw_db:
    while True:
        buffer = raw_db.read(PAGE_SIZE)
        with (output_path / f"{i:03d}").open("wb") as out_file:
            out_file.write(buffer)
        if len(buffer) < PAGE_SIZE:
            break
        i += 1
