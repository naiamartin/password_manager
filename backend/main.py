from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import secrets
from fastapi import HTTPException
from backend.credentials import CredentialVault


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

# Will store the vault for each logged-in user
activeVaults = {}


# Will get the logged-in user's vault
def get_vault(request: Request):

    # Will get the session ID from the browser
    sessionId = request.cookies.get("sessionId")


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

     # Will open the user's password vault
    vault = CredentialVault( DATABASE_PATH, message, master_password)

    # Will create a session ID for the logged-in user
    sessionId = secrets.token_urlsafe(32)

    # Will store the user's vault
    activeVaults[sessionId] = vault

    # Will go to the accounts page
    response = RedirectResponse("/accounts", status_code=303)

    # Will remember the logged-in user by setting a cookie in the browser
    response.set_cookie( "sessionId", sessionId, httponly=True, samesite="lax")

    return response

    #ADD ACCOUNT
@app.get("/add")
async def add_page(request: Request):
    # will display the add_account.html webpage in the browser.
    return templates.TemplateResponse(request=request, name="add_account.html")


###ADD

# Will save a new account
@app.post("/add")
async def add_account(request: Request, platform_name: str = Form(...),username: str = Form(...), password: str = Form(...)):

    # Will logged-in user's password vault
    vault = get_vault(request)

    # Save the users account details
    vault.add_credential(platform_name, username, password)

    # Will go to the View Accounts page
    return RedirectResponse("/view", status_code=303)



###VIEW ACCOUNT

# Will show all thesaved accounts
@app.get("/view")
async def view_accounts(request: Request):

    # Will get the logged-in user's password vault
    vault = get_vault(request)

    # Get all saved accounts from the vault
    accounts = vault.show_credentials()

    # Shows all accounts on the View Accounts page
    return templates.TemplateResponse(request=request, name="view.html", context={"accounts": accounts}
    )


###EDIT ACCOUNT
@app.get("/edit")
async def edit_page(request: Request):
    # Will see if the user is logged in
    get_vault(request)

    # will display the edit_account.html webpage in the browser.
    return templates.TemplateResponse(request=request, name="edit_account.html")


@app.post("/edit")
# This will handle the edit account page form submission
async def edit_account( request: Request, account_id: int, platform_name: str = Form(...), username: str = Form(...), password: str = Form(...),
):
    # Will get the logged-in user's vault
    vault = get_vault(request)

    # Gives the saved account details update with the new details
    vault.edit_credential(account_id, platform_name, username, password)

    # Will go to the view accounts page
    return RedirectResponse("/view", status_code=303)


###DELETE ACCOUNT
# Want to delete a saved account
@app.post("/delete")
async def delete_account( request: Request, account_id: int = Form(...)):

    # Will the logged-in user's password vault
    vault = get_vault(request)

    # Delete the account using its ID
    vault.delete_credential(account_id)

    # Go back to the View Accounts page
    return RedirectResponse("/view", status_code=303)


@app.get("/delete")
async def delete_page(request: Request):

    # Sees of user is logged in
    get_vault(request)

    # show the delete dccount webpage
    return templates.TemplateResponse(request=request,name="delete_account.html")