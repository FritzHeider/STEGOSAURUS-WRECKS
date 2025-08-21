import zlib
from PIL import Image


def _extract_bits(image, plane):
    img = image.convert("RGBA")
    width, height = img.size
    planes = list(plane)
    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b, a = img.getpixel((x, y))
            channels = {'R': r, 'G': g, 'B': b, 'A': a}
            for p in planes:
                bits.append(str(channels[p] & 1))
                if ''.join(bits[-8:]) == '00000000':
                    return ''.join(bits[:-8])
    return ''.join(bits)


def decode_text_from_plane(image, plane="RGB"):
    """Decode hidden text from the specified color plane."""
    bits = _extract_bits(image, plane)
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(c, 2)) for c in chars if c)


def _bit_stream(image, plane):
    img = image.convert("RGBA")
    width, height = img.size
    planes = list(plane)
    for y in range(height):
        for x in range(width):
            r, g, b, a = img.getpixel((x, y))
            channels = {'R': r, 'G': g, 'B': b, 'A': a}
            for p in planes:
                yield str(channels[p] & 1)


def decode_zlib_from_image(image, plane="RGB"):
    """Decode and decompress data hidden in the image."""
    stream = _bit_stream(image, plane)
    length_bits = ''.join(next(stream) for _ in range(32))
    length = int(length_bits, 2)
    data_bits = ''.join(next(stream) for _ in range(length * 8))
    data = bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))
    return zlib.decompress(data)
