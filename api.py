from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from PIL import Image
import base64
import uuid
import os

from app import (
    encode_text_into_plane,
    decode_text_from_plane,
    encode_zlib_into_image,
    decode_zlib_from_image,
)
from share_utils import increment_share

app = FastAPI()


@app.post("/encode/text")
async def encode_text(image: UploadFile = File(...), text: str = Form(...), plane: str = Form("RGB")):
    data = await image.read()
    temp_in = f"/tmp/{uuid.uuid4()}_{image.filename}"
    with open(temp_in, "wb") as f:
        f.write(data)
    img = Image.open(temp_in)
    temp_out = f"/tmp/{uuid.uuid4()}.png"
    encode_text_into_plane(img, text, temp_out, plane)
    with open(temp_out, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    os.remove(temp_in)
    os.remove(temp_out)
    return {"image_base64": b64}


@app.post("/decode/text")
async def decode_text(image: UploadFile = File(...), plane: str = Form("RGB")):
    data = await image.read()
    temp_in = f"/tmp/{uuid.uuid4()}_{image.filename}"
    with open(temp_in, "wb") as f:
        f.write(data)
    img = Image.open(temp_in)
    text = decode_text_from_plane(img, plane)
    os.remove(temp_in)
    return {"text": text}


@app.post("/encode/zlib")
async def encode_zlib(image: UploadFile = File(...), file: UploadFile = File(...), plane: str = Form("RGB")):
    image_bytes = await image.read()
    tmp_img = f"/tmp/{uuid.uuid4()}_{image.filename}"
    with open(tmp_img, "wb") as f:
        f.write(image_bytes)
    file_bytes = await file.read()
    img = Image.open(tmp_img)
    tmp_out = f"/tmp/{uuid.uuid4()}.png"
    encode_zlib_into_image(img, file_bytes, tmp_out, plane)
    with open(tmp_out, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    os.remove(tmp_img)
    os.remove(tmp_out)
    return {"image_base64": b64}


@app.post("/decode/zlib")
async def decode_zlib(image: UploadFile = File(...), plane: str = Form("RGB")):
    data = await image.read()
    tmp_img = f"/tmp/{uuid.uuid4()}_{image.filename}"
    with open(tmp_img, "wb") as f:
        f.write(data)
    img = Image.open(tmp_img)
    file_bytes = decode_zlib_from_image(img, plane)
    os.remove(tmp_img)
    b64 = base64.b64encode(file_bytes).decode()
    return {"file_base64": b64}


@app.get("/share/{share_id}")
def shared_image(share_id: str):
    path = increment_share(share_id)
    if not path:
        raise HTTPException(status_code=404, detail="Share not found")
    return FileResponse(path, media_type="image/png")
