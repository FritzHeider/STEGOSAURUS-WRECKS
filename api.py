from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from PIL import Image
import base64
import uuid
import os
from typing import List

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
    paths = encode_text_into_plane(img, text, temp_out, plane)
    images_b64 = []
    for p in paths:
        with open(p, "rb") as f:
            images_b64.append(base64.b64encode(f.read()).decode())
        os.remove(p)
    os.remove(temp_in)
    return {"images_base64": images_b64}


@app.post("/decode/text")
async def decode_text(images: List[UploadFile] = File(...), plane: str = Form("RGB")):
    temps = []
    imgs = []
    for image in images:
        data = await image.read()
        temp_in = f"/tmp/{uuid.uuid4()}_{image.filename}"
        with open(temp_in, "wb") as f:
            f.write(data)
        imgs.append(Image.open(temp_in))
        temps.append(temp_in)
    text = decode_text_from_plane(imgs, plane)
    for t in temps:
        os.remove(t)
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
    paths = encode_zlib_into_image(img, file_bytes, tmp_out, plane)
    images_b64 = []
    for p in paths:
        with open(p, "rb") as f:
            images_b64.append(base64.b64encode(f.read()).decode())
        os.remove(p)
    os.remove(tmp_img)
    return {"images_base64": images_b64}


@app.post("/decode/zlib")
async def decode_zlib(images: List[UploadFile] = File(...), plane: str = Form("RGB")):
    temps = []
    imgs = []
    for image in images:
        data = await image.read()
        tmp_img = f"/tmp/{uuid.uuid4()}_{image.filename}"
        with open(tmp_img, "wb") as f:
            f.write(data)
        imgs.append(Image.open(tmp_img))
        temps.append(tmp_img)
    file_bytes = decode_zlib_from_image(imgs, plane)
    for t in temps:
        os.remove(t)
    b64 = base64.b64encode(file_bytes).decode()
    return {"file_base64": b64}


@app.get("/share/{share_id}")
def shared_image(share_id: str):
    path = increment_share(share_id)
    if not path:
        raise HTTPException(status_code=404, detail="Share not found")
    return FileResponse(path, media_type="image/png")
