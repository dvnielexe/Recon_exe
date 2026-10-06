import json
from pathlib import Path

def save_json(output_dir: str, filename: str, data):
    output_path = Path(output_dir) / filename

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return output_path