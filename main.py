from typing import Union
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from datetime import datetime, timedelta
import cv2
import numpy as np
from PIL import Image
import torch
import io

app = FastAPI()

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Union[str, None] = None

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return token_data

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Replace with your own authentication logic
    if form_data.username != "testuser" or form_data.password != "testpassword":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
async def read_root(token: str = Depends(oauth2_scheme)):
    return {"Hello": "World"}

@app.get("/items/{item_id}")
async def read_item(item_id: int, q: Union[str, None] = None, token: str = Depends(oauth2_scheme)):
    verify_token(token)
    return {"item_id": item_id, "q": q}

@app.post("/detect/")
async def detect_image(file: UploadFile = File(...)):
    image = read_imagefile(await file.read())
    image_np = np.array(image)
    results = model(image_np)
    results = results.xyxy[0].numpy()
    image_np = draw_boxes(results, image_np)
    
    # Convert back to PIL Image
    image = Image.fromarray(image_np.astype('uint8'), 'RGB')
    
    # Save image to a bytes buffer
    buf = io.BytesIO()
    image.save(buf, format='JPEG')
    buf.seek(0)
    
    return StreamingResponse(buf, media_type="image/jpeg")
