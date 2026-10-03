import os
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from ..core.database import db
from ..core.security import verify_password, get_password_hash, create_access_token

router = APIRouter(prefix="/auth", tags=["Authentication"])
users_collection = db["users"]

class UserRegister(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    username: str
    password: str

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister):
    existing_user = await users_collection.find_one({
        "$or": [{"email": user_data.email.lower()}, {"username": user_data.username}]
    })
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered."
        )

    user_dict = {
        "email": user_data.email.lower(),
        "username": user_data.username,
        "hashed_password": get_password_hash(user_data.password),
        "role": "analyst"
    }
    result = await users_collection.insert_one(user_dict)
    return {"id": str(result.inserted_id), "message": "User registered successfully."}

@router.post("/login")
async def login(credentials: UserLogin):
    user = await users_collection.find_one({"username": credentials.username})
    if not user or not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )

    token = create_access_token(data={"sub": user["username"], "role": user.get("role", "analyst")})
    return {"access_token": token, "token_type": "bearer"}