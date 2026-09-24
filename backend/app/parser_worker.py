import base64
import json
import sys

from .extractors import extract_text_in_process


def main() -> None:
    request = json.loads(sys.stdin.read())
    content = base64.b64decode(request["content"])
    text, source_type = extract_text_in_process(request["filename"], content)
    print(json.dumps({"text": text, "source_type": source_type}, ensure_ascii=False))


if __name__ == "__main__":
    main()
