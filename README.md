# Stegosaurus Wrecks

This project hides data inside images using least significant bit (LSB) steganography.

## Security Scheme

Each payload is encoded with a 32-bit length and a CRC32 checksum before being
embedded. During decoding, the length and checksum are verified to detect
truncation or tampering. Images encoded prior to this scheme that lack the
checksum are still supported through a legacy terminator-based fallback.

## REST API

Encode and decode images through a FastAPI service. The endpoints return
base64-encoded images or data so responses can be used directly in web or
social media integrations. When encoding, a shareable URL is also generated
that serves the resulting image.

### `POST /encode/text`

Hide a text message inside an image.

- `image`: cover image file
- `text`: message to embed
- `plane` (optional): color channels to use (`RGB` by default)

**Response**

```json
{
  "image_base64": "...",
  "share_url": "/share/<id>"
}
```

**Example**

```bash
curl -F "image=@cover.png" -F "text=hello" \
  http://localhost:8000/encode/text
```

### `POST /decode/text`

Extract a hidden text message from an image.

- `image`: steganographic image file
- `plane` (optional): channels used during encoding

```bash
curl -F "image=@encoded.png" \
  http://localhost:8000/decode/text
```

### `POST /encode/zlib`

Embed arbitrary file data using zlib compression.

- `image`: cover image file
- `file`: file to hide
- `plane` (optional)

```bash
curl -F "image=@cover.png" -F "file=@secret.zip" \
  http://localhost:8000/encode/zlib
```

### `POST /decode/zlib`

Recover a file that was previously embedded with the zlib endpoint.

```bash
curl -F "image=@encoded.png" \
  http://localhost:8000/decode/zlib
```

### `GET /share/{share_id}`

Serve an encoded image by its share identifier. Share URLs returned from the
encode endpoints point here and can be posted directly to social platforms.

```bash
curl http://localhost:8000/share/<id> --output shared.png
```
