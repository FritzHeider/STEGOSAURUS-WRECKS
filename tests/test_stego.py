import os
import sys

from PIL import Image

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from stego import encode_text_into_plane, decode_text_from_plane


def test_encode_decode_roundtrip(tmp_path):
    img = Image.new("RGBA", (50, 50), color=(255, 255, 255, 255))
    text = "hello world"
    out_path = tmp_path / "encoded.png"
    encode_text_into_plane(img, text, str(out_path), plane="RGB", password="secret")
    out_img = Image.open(out_path)
    decoded = decode_text_from_plane(out_img, plane="RGB", password="secret")
    assert decoded == text
 
