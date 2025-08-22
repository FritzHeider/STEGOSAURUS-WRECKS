# Stegosaurus Wrecks API

This repository exposes LSB steganography encode/decode utilities through a FastAPI service and Streamlit UI.

## Running the API

```bash
uvicorn api:app --reload
```

## Endpoints

### `POST /encode/text`
Embed UTF-8 text into an image.

- **form fields**: `image` (file), `text`, `plane` (optional, default `RGB`)
- **response**: base64 encoded image plus shareable links

Example:
```bash
curl -F "image=@stegg.png" -F "text=hello" http://localhost:8000/encode/text
```

### `POST /decode/text`
Extract UTF-8 text from an image.

- **form fields**: `image` (file), `plane` (optional)

Example:
```bash
curl -F "image=@encoded.png" http://localhost:8000/decode/text
```

### `POST /encode/zlib`
Embed a binary file (zlib compressed) into an image.

- **form fields**: `image` (file), `file` (file), `plane` (optional)
- **response**: base64 encoded image plus shareable links

Example:
```bash
curl -F "image=@stegg.png" -F "file=@secret.txt" http://localhost:8000/encode/zlib
```

### `POST /decode/zlib`
Extract a zlib-compressed binary from an image.

- **form fields**: `image` (file), `plane` (optional)
- **response**: base64 encoded binary

Example:
```bash
curl -F "image=@encoded.png" http://localhost:8000/decode/zlib
```

### `GET /share/{share_id}`
Retrieve an encoded image by its share identifier.

Share links returned by the encode endpoints point to this route, and a `tweet_url` is provided for quick social sharing.

