from __future__ import annotations

import os
import base64
import zlib
from typing import List

from PIL import Image

from security import encrypt_data, decrypt_data


# --- Image helpers ------------------------------------------------------------
def convert_to_png(image_path):
    """Convert the image to PNG format if it's not already in PNG."""
    if hasattr(image_path, "seek"):
        try:
            image_path.seek(0)
        except Exception:
            pass
    img = Image.open(image_path)
    if img.format != "PNG":
        new_image_path = os.path.splitext(getattr(image_path, "name", "image"))[0] + ".png"
        img.save(new_image_path, "PNG")
        return new_image_path
    return image_path


def compress_image_before_encoding(src_image, output_image_path: str, max_kb: int = 900):
    """Save image as PNG and iteratively downscale by 50% until under max_kb."""
    if hasattr(src_image, "seek"):
        try:
            src_image.seek(0)
        except Exception:
            pass
    img = Image.open(src_image).convert("RGBA")
    img.save(output_image_path, optimize=True, format="PNG")

    while os.path.getsize(output_image_path) > max_kb * 1024:
        img = Image.open(output_image_path).convert("RGBA")
        if img.width <= 16 or img.height <= 16:
            break
        img = img.resize((max(16, img.width // 2), max(16, img.height // 2)))
        img.save(output_image_path, optimize=True, format="PNG")


# --- LSB stego core -----------------------------------------------------------
_CHANNEL_INDEX = {"R": 0, "G": 1, "B": 2, "A": 3}


def _channels_for_plane(plane: str) -> List[int]:
    plane = plane.upper()
    if plane == "RGB":
        return [_CHANNEL_INDEX["R"], _CHANNEL_INDEX["G"], _CHANNEL_INDEX["B"]]
    return [_CHANNEL_INDEX[c] for c in plane if c in _CHANNEL_INDEX]


def _bytes_to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def _embed_bits(img: Image.Image, bits: str, plane: str) -> Image.Image:
    img = img.convert("RGBA")
    width, height = img.size
    channels = _channels_for_plane(plane)
    capacity = width * height * len(channels)
    if len(bits) > capacity:
        raise ValueError(
            f"Payload too large for image/channel capacity ({len(bits)} bits > {capacity} bits)."
        )

    idx = 0
    for y in range(height):
        for x in range(width):
            r, g, b, a = img.getpixel((x, y))
            vals = [r, g, b, a]
            for ch in channels:
                if idx >= len(bits):
                    img.putpixel((x, y), tuple(vals))
                    return img
                vals[ch] = (vals[ch] & 0xFE) | int(bits[idx])
                idx += 1
            img.putpixel((x, y), tuple(vals))
    return img


def _extract_bits(img: Image.Image, plane: str, bits_needed: int | None = None) -> str:
    img = img.convert("RGBA")
    width, height = img.size
    channels = _channels_for_plane(plane)
    bits: List[str] = []
    for y in range(height):
        for x in range(width):
            r, g, b, a = img.getpixel((x, y))
            vals = [r, g, b, a]
            for ch in channels:
                bits.append(str(vals[ch] & 1))
                if bits_needed is not None and len(bits) >= bits_needed:
                    return "".join(bits)
    return "".join(bits)


# --- High-level encode/decode -------------------------------------------------
def _frame_with_length(data: bytes) -> str:
    length = len(data)
    header_bits = f"{length:032b}"
    return header_bits + _bytes_to_bits(data)


def _deframe_with_length_or_terminator(all_bits: str) -> bytes:
    if len(all_bits) >= 32:
        declared_len = int(all_bits[:32], 2)
        total_bits_needed = 32 + declared_len * 8
        if declared_len > 0 and total_bits_needed <= len(all_bits):
            payload_bits = all_bits[32:32 + declared_len * 8]
            return _bits_to_bytes(payload_bits)

    full_bytes_len = (len(all_bits) // 8) * 8
    bytes_stream = [all_bits[i : i + 8] for i in range(0, full_bytes_len, 8)]
    out = bytearray()
    for b in bytes_stream:
        if b == "00000000":
            break
        out.append(int(b, 2))
    if not out:
        raise ValueError("No hidden payload found.")
    return bytes(out)


def encode_text_into_plane(
    image: Image.Image,
    text: str,
    output_path: str,
    plane: str = "RGB",
    password: str | None = None,
):
    if password:
        token = encrypt_data(text.encode("utf-8"), password)
        to_store = base64.b64encode(token)
    else:
        to_store = text.encode("utf-8")

    framed_bits = _frame_with_length(to_store)
    out_img = _embed_bits(image.convert("RGBA"), framed_bits, plane)
    out_img.save(output_path, format="PNG")


def encode_zlib_into_image(
    image: Image.Image,
    file_data: bytes,
    output_path: str,
    plane: str = "RGB",
    password: str | None = None,
):
    compressed = zlib.compress(file_data)
    payload = encrypt_data(compressed, password) if password else compressed
    framed_bits = _frame_with_length(payload)
    out_img = _embed_bits(image.convert("RGBA"), framed_bits, plane)
    out_img.save(output_path, format="PNG")


def decode_text_from_plane(
    image: Image.Image,
    plane: str = "RGB",
    password: str | None = None,
) -> str:
    bits = _extract_bits(image, plane, bits_needed=None)
    raw = _deframe_with_length_or_terminator(bits)

    if password:
        try:
            token = base64.b64decode(raw, validate=True)
            decrypted = decrypt_data(token, password)
            return decrypted.decode("utf-8", errors="strict")
        except Exception as e:
            raise ValueError("Failed to decrypt hidden text.") from e
    else:
        try:
            return raw.decode("utf-8", errors="strict")
        except Exception as e:
            raise ValueError("Hidden text is not valid UTF-8.") from e


def decode_zlib_from_image(
    image: Image.Image,
    plane: str = "RGB",
    password: str | None = None,
) -> bytes:
    bits = _extract_bits(image, plane, bits_needed=None)
    payload = _deframe_with_length_or_terminator(bits)

    if password:
        try:
            payload = decrypt_data(payload, password)
        except Exception as e:
            raise ValueError("Failed to decrypt hidden data.") from e

    try:
        return zlib.decompress(payload)
    except zlib.error as e:
        raise ValueError("Failed to decompress hidden data.") from e


# --- Download helper ----------------------------------------------------------
def get_image_download_link(img_path: str) -> str:
    with open(img_path, "rb") as f:
        img_bytes = f.read()
    b64 = base64.b64encode(img_bytes).decode()
    name = os.path.basename(img_path)
    return f'<a href="data:image/png;base64,{b64}" download="{name}">Download {name}</a>'
