import os
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette.responses import StreamingResponse
from starlette.middleware.sessions import SessionMiddleware
from database import init_db, get_db, User
from models import UserRegister, UserOut, Token
from auth import (
    hash_password, verify_password, create_access_token, decode_token,
    get_current_user, require_roles, oauth, GOOGLE_CALLBACK_URL
)
from audit import log_action
from mfa import generate_mfa_secret, get_mfa_uri, verify_mfa
from email_utils import send_email
import qrcode
import io

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "replace-this"))

init_db()

@app.post("/register", response_model=UserOut)
def register(user: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username exists")
    hashed = hash_password(user.password)
    db_user = User(username=user.username, password_hash=hashed, email=user.email)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    log_action(user.username, "register")
    return db_user

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == form_data.username).first()
    if not db_user or not verify_password(form_data.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect credentials")
    # Check if MFA is enabled
    if db_user.mfa_secret:
        raise HTTPException(status_code=206, detail="MFA required")  # Custom status for MFA required
    token = create_access_token({"sub": db_user.username, "role": db_user.role})
    log_action(db_user.username, "login")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/login-mfa", response_model=Token)
def login_mfa(
    username: str = Form(...),
    password: str = Form(...),
    mfa_code: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.mfa_secret:
        if not verify_mfa(user.mfa_secret, mfa_code):
            raise HTTPException(status_code=401, detail="Invalid MFA code")
    token = create_access_token({"sub": user.username, "role": user.role})
    log_action(user.username, "login-mfa")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/mfa/setup")
def mfa_setup(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    secret = generate_mfa_secret()
    current_user.mfa_secret = secret
    db.commit()
    uri = get_mfa_uri(current_user.username, secret)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")

@app.post("/request-reset")
def request_reset(email: str = Form(...), background_tasks: BackgroundTasks = BackgroundTasks(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    reset_token = create_access_token({"sub": user.username, "action": "reset"}, expires_delta=15)
    reset_link = f"http://localhost:8000/reset-password?token={reset_token}"
    background_tasks.add_task(send_email, to=email, subject="Reset Your Password", body=f"Reset: {reset_link}")
    return {"msg": "Reset link sent."}

@app.post("/reset-password")
def reset_password(token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    payload = decode_token(token)
    if payload.get("action") != "reset":
        raise HTTPException(status_code=400, detail="Invalid token.")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    user.password_hash = hash_password(new_password)
    db.commit()
    return {"msg": "Password changed."}

@app.get("/auth/google/login")
async def login_with_google(request: Request):
    return await oauth.google.authorize_redirect(request, GOOGLE_CALLBACK_URL)

@app.get("/auth/google/callback")
async def auth_with_google(request: Request, db: Session = Depends(get_db)):
    token = await oauth.google.authorize_access_token(request)
    userinfo = await oauth.google.parse_id_token(request, token)
    email = userinfo["email"]
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(username=email, email=email, role="user")
        db.add(user)
        db.commit()
        db.refresh(user)
    jwt_token = create_access_token({"sub": user.username, "role": user.role})
    log_action(user.username, "google-login")
    return {"token": jwt_token, "user": {"username": user.username, "email": user.email}}

@app.get("/me", response_model=UserOut)
def me(user=Depends(get_current_user)):
    return user

@app.get("/admin")
def admin_only(user=Depends(require_roles("admin"))):
    return {"msg": f"Hello, {user.username}, you are an admin!"}

@app.get("/audit")
def audit_logs(db: Session = Depends(get_db), user=Depends(require_roles("admin"))):
    logs = db.execute("SELECT username, action, timestamp FROM audit_logs ORDER BY timestamp DESC").fetchall()
    return [{"username": row[0], "action": row[1], "timestamp": row[2]} for row in logs]