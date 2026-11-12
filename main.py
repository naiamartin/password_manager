from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.account_setup import (
    # import the functions from account_setup.py
    initialise_database,
    register_user,
    login_user,
)

FRONTEND = Path("frontend")
STATIC_FILES = FRONTEND / "static"
DATABASE_PATH = Path("users.db")

initialise_database(DATABASE_PATH)  #ensure the database is initialized at startup

app = FastAPI(title="Password Manager")
app.mount("/static", StaticFiles(directory=STATIC_FILES), name="static")
templates = Jinja2Templates(directory=FRONTEND)


@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse(
        # render the index.html template
        request=request,
        name="index.html",
        context={"username": None},
    )


@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse(
        # render the register.html template
        request=request,
        name="register.html",
    )


@app.post("/register")
async def register(
    #handle the registration form submission
    request: Request,
    username: str = Form(...), #ensure str type for username and master_password
    master_password: str = Form(...),
):
    success, message = register_user(DATABASE_PATH, username, master_password)
    if success:
        # redirect to the login page with a success message (code 303 for redirect after POST)
        return RedirectResponse("/login?registered=1", status_code=303)

    return templates.TemplateResponse(
        #render the register.html template with an error message if registration fails
        request=request,
        name="register.html",
        context={"message": message},
        status_code=400,
    )


@app.get("/login")
async def login_page(request: Request):
    message = (
        #display a success message if the user has just registered
        "Account created. You can now log in."
        if request.query_params.get("registered") == "1"
        else None
    )
    return templates.TemplateResponse(
        #render the login.html template with a message
        request=request,
        name="login.html",
        context={"message": message},
    )


@app.post("/login")
async def login(
    #handle the login form submission
    request: Request,
    username: str = Form(...),
    master_password: str = Form(...),
):
    success, message = login_user(DATABASE_PATH, username, master_password)
    if not success:
        #render the login.html template with an error message if login fails
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"message": message},
            status_code=400,
        )

    return templates.TemplateResponse(
        #render the index.html template with the username if login is successful
        request=request,
        name="index.html",
        context={"username": username.strip()},
    )
