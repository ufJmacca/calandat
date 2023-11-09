"""
    Module is responsible for declaring FastAPI endpoints.
"""
from datetime import timedelta

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import (
    OAuth2PasswordRequestForm,
)
from authentication import (
    Token,
    authenicate_user,
    pwd_context,
    create_jwt,
    User,
    get_current_active_user,
)

ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

templates = Jinja2Templates(directory="templates")

# Temporary db, remove and replace in autentication.py
fake_db = {
    "test": {
        "username": "test",
        "full_name": "test user",
        "email": "test@user.com",
        "hashed_password": pwd_context.hash("hello world"),
        "disabled": False,
    }
}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenicate_user(fake_db, form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    access_token = create_jwt(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/bearer/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/items/", response_class=HTMLResponse)
async def read_items(
    request: Request, _: User = Depends(get_current_active_user)
) -> HTMLResponse:
    context = {"request": request}
    return templates.TemplateResponse(name="items.html", context=context)


@app.get("/signin", response_class=HTMLResponse)
async def login(request: Request) -> HTMLResponse:
    context = {"request": request}
    return templates.TemplateResponse(name="signin.html", context=context)
