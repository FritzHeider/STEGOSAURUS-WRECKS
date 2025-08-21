from PIL import Image

import sys
import pathlib

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))

from app import (
    encode_text_into_plane,
    decode_text_from_plane,
    encode_zlib_into_image,
    decode_zlib_from_image,
)


def test_text_roundtrip(tmp_path):
    img = Image.new("RGBA", (10, 10), color=(255, 255, 255, 255))
    out_path = tmp_path / "encoded_text.png"
    encode_text_into_plane(img, "hello world", str(out_path), plane="RGB")
    encoded_img = Image.open(out_path)
    result = decode_text_from_plane(encoded_img, "RGB")
    assert result == "hello world"


def test_zlib_roundtrip(tmp_path):
    img = Image.new("RGBA", (10, 10), color=(255, 255, 255, 255))
    out_path = tmp_path / "encoded_bin.png"
    data = b"binarydata"
    encode_zlib_into_image(img, data, str(out_path), plane="RGB")
    encoded_img = Image.open(out_path)
    result = decode_zlib_from_image(encoded_img, "RGB")
    assert result == data
