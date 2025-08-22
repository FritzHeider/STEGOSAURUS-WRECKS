import os
import sys

from PIL import Image

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from app import (
    encode_text_into_plane,
    decode_text_from_plane,
    encode_zlib_into_image,
    decode_zlib_from_image,
)


def test_encode_decode_text_roundtrip(tmp_path):
    img = Image.new("RGBA", (40, 40), color=(255, 255, 255, 255))
    message = "sequential channels"
    out_path = tmp_path / "encoded_text.png"

    paths = encode_text_into_plane(img, message, str(out_path), plane="RGB")
    images = [Image.open(p) for p in paths]
    decoded = decode_text_from_plane(images, plane="RGB")
    assert decoded == message


def test_encode_decode_file_roundtrip(tmp_path):
    img = Image.new("RGBA", (50, 50), color=(255, 255, 255, 255))
    data = b"binary payload for testing"
    out_path = tmp_path / "encoded_file.png"

    paths = encode_zlib_into_image(img, data, str(out_path), plane="RGB")
    images = [Image.open(p) for p in paths]
    recovered = decode_zlib_from_image(images, plane="RGB")
    assert recovered == data
