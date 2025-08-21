import os
import zlib
from PIL import Image


def convert_to_png(image_path):
    """Convert the image to PNG format if it's not already in PNG."""
    img = Image.open(image_path)
    if img.format != 'PNG':
        new_image_path = os.path.splitext(image_path)[0] + '.png'
        img.save(new_image_path, 'PNG')
        return new_image_path
    return image_path


def compress_image_before_encoding(image_path, output_image_path):
    """Compress the image before encoding to ensure it is below 900 KB."""
    img = Image.open(image_path)
    img.save(output_image_path, optimize=True, format="PNG")
    while os.path.getsize(output_image_path) > 900 * 1024:
        img = Image.open(output_image_path)
        img = img.resize((img.width // 2, img.height // 2))
        img.save(output_image_path, optimize=True, format="PNG")


def _embed_bit(value, bit):
    return (value & 0xFE) | int(bit)


def encode_text_into_plane(image, text, output_path, plane="RGB"):
    """Embed the text into a specific color plane (R, G, B, A)."""
    img = image.convert("RGBA")
    width, height = img.size
    binary_text = ''.join(format(ord(char), '08b') for char in text) + '00000000'
    index = 0
    planes = list(plane)
    for y in range(height):
        for x in range(width):
            if index >= len(binary_text):
                break
            r, g, b, a = img.getpixel((x, y))
            channels = {'R': r, 'G': g, 'B': b, 'A': a}
            for p in planes:
                if index < len(binary_text):
                    channels[p] = _embed_bit(channels[p], binary_text[index])
                    index += 1
            img.putpixel((x, y), (channels['R'], channels['G'], channels['B'], channels['A']))
        if index >= len(binary_text):
            break
    img.save(output_path, format="PNG")


def encode_zlib_into_image(image, file_data, output_path, plane="RGB"):
    """Embed zlib-compressed binary data into a specific color plane (R, G, B, A)."""
    compressed_data = zlib.compress(file_data)
    length = len(compressed_data)
    binary_length = format(length, '032b')
    binary_payload = ''.join(format(byte, '08b') for byte in compressed_data)
    binary_data = binary_length + binary_payload
    img = image.convert("RGBA")
    width, height = img.size
    index = 0
    planes = list(plane)
    for y in range(height):
        for x in range(width):
            if index >= len(binary_data):
                break
            r, g, b, a = img.getpixel((x, y))
            channels = {'R': r, 'G': g, 'B': b, 'A': a}
            for p in planes:
                if index < len(binary_data):
                    channels[p] = _embed_bit(channels[p], binary_data[index])
                    index += 1
            img.putpixel((x, y), (channels['R'], channels['G'], channels['B'], channels['A']))
        if index >= len(binary_data):
            break
    img.save(output_path, format="PNG")
