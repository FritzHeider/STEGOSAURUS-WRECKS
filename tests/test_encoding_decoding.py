from PIL import Image

from stego.encoding import encode_text_into_plane, encode_zlib_into_image
from stego.decoding import decode_text_from_plane, decode_zlib_from_image


def test_encode_decode_text(tmp_path):
    image = Image.new('RGB', (10, 10), color='white')
    output_path = tmp_path / 'encoded.png'
    encode_text_into_plane(image, 'hello', str(output_path), 'RGB')
    encoded_image = Image.open(output_path)
    result = decode_text_from_plane(encoded_image, 'RGB')
    assert result == 'hello'


def test_encode_decode_zlib(tmp_path):
    data = b'hello world'
    image = Image.new('RGB', (20, 20), color='white')
    output_path = tmp_path / 'encoded.png'
    encode_zlib_into_image(image, data, str(output_path), 'RGB')
    encoded_image = Image.open(output_path)
    decoded_data = decode_zlib_from_image(encoded_image, 'RGB')
    assert decoded_data == data
