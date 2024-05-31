from core import parser
from pathlib import Path

FILE_PATH = Path("../dump")

if __name__ == "__main__":
    _parser = parser.Parser(FILE_PATH)
    # _parser.view_data()