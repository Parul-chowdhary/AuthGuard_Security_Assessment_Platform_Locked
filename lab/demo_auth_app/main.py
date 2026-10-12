"""
AuthGuard Demonstration Lab Application
=======================================
A safe, isolated target application designed for controlled authentication audits.
Supports dual modes: 'vulnerable' (demonstrates flaw patterns) and 'secure' (demonstrates defense controls).
"""

from typing import Dict, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel

app = FastAPI(title="AuthGuard Demonstration Authentication Testbed")

# Testbed in-memory state
LAB_STATE = {
    "mode": "vulnerable",  # 'vulnerable' or 'secure'
    "used_otps": set(),
    "otp_failed_attempts": {},
    "login_failed_attempts": {},
    "used_captcha_tokens": set(),
}


class LoginRequest(BaseModel):
    username: str
    password: str
    captcha_token: Optional[str] = None


class OtpRequest(BaseModel):
    username: Optional[str] = None
    otp: str
    retest_replay: Optional[bool] = False


@app.get("/api/config")
def get_config():
    return {"lab": "AuthGuard Demo Lab", "mode": LAB_STATE["mode"]}


@app.post("/api/mode/{mode}")
def set_mode(mode: str):
    if mode not in ("vulnerable", "secure"):
        raise HTTPException(status_code=400, detail="Mode must be 'vulnerable' or 'secure'")
    LAB_STATE["mode"] = mode
    # Reset attempt tracking
    LAB_STATE["used_otps"].clear()
    LAB_STATE["otp_failed_attempts"].clear()
    LAB_STATE["login_failed_attempts"].clear()
    LAB_STATE["used_captcha_tokens"].clear()
    return {"status": "ok", "mode": LAB_STATE["mode"]}


@app.post("/login")
def login(req: LoginRequest, response: Response):
    mode = LAB_STATE["mode"]

    if mode == "vulnerable":
        # Flaw 1: Discloses user existence
        if req.username != "admin" and req.username != "testuser":
            raise HTTPException(status_code=404, detail="User not found")

        # Flaw 2: Accepts forged or missing CAPTCHA
        # Flaw 3: No rate limiting (does not check or return 429)
        if req.password not in ("ValidPassword123!", "TestPassword123!"):
            raise HTTPException(status_code=401, detail="Invalid password for user")

        return {"status": "success", "token": "vulnerable_session_token_123"}

    else:
        # SECURE MODE
        # Defense 1: Enforce CAPTCHA
        if not req.captcha_token:
            raise HTTPException(status_code=400, detail="CAPTCHA token required")
        if req.captcha_token.startswith("FORGED_"):
            raise HTTPException(status_code=400, detail="Invalid CAPTCHA token")
        if req.captcha_token in LAB_STATE["used_captcha_tokens"]:
            raise HTTPException(status_code=400, detail="CAPTCHA token already used")
        LAB_STATE["used_captcha_tokens"].add(req.captcha_token)

        # Defense 2: Rate Limiting
        attempts = LAB_STATE["login_failed_attempts"].get(req.username, 0)
        if attempts >= 5:
            response.headers["Retry-After"] = "60"
            response.headers["X-RateLimit-Remaining"] = "0"
            raise HTTPException(status_code=429, detail="Too Many Requests. Try again in 60s.")

        # Defense 3: Uniform error messages (No account enumeration)
        if req.username != "testuser" or req.password != "ValidPassword123!":
            LAB_STATE["login_failed_attempts"][req.username] = attempts + 1
            response.headers["X-RateLimit-Remaining"] = str(max(0, 5 - (attempts + 1)))
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Reset attempts upon successful login
        LAB_STATE["login_failed_attempts"][req.username] = 0
        return {"status": "success", "token": "secure_session_token_xyz"}


@app.post("/verify-otp")
def verify_otp(req: OtpRequest):
    mode = LAB_STATE["mode"]

    if mode == "vulnerable":
        # Flaw 1: Accepts '000000' dummy code or arbitrary inputs
        if req.otp == "000000":
            return {"status": "success", "message": "OTP verification bypassed!"}

        # Flaw 2: Allows replay of OTP
        if req.otp == "123456":
            return {"status": "success", "message": "OTP verified (reusable)"}

        # Flaw 3: Does not require username binding
        if not req.username:
            return {"status": "success", "message": "Unbound OTP accepted"}

        # Flaw 4: No attempt quota / rate limit
        raise HTTPException(status_code=400, detail="Incorrect code")

    else:
        # SECURE MODE
        # Defense 1: Strict account binding
        if not req.username:
            raise HTTPException(status_code=400, detail="Username and session binding required")

        # Defense 2: Attempt limiting
        attempts = LAB_STATE["otp_failed_attempts"].get(req.username, 0)
        if attempts >= 3:
            raise HTTPException(status_code=429, detail="OTP attempts exceeded. Session locked.")

        # Defense 3: Replay prevention
        if req.otp in LAB_STATE["used_otps"]:
            raise HTTPException(status_code=400, detail="OTP has already been used.")

        # Defense 4: Rejects invalid code
        if req.otp != "123456":
            LAB_STATE["otp_failed_attempts"][req.username] = attempts + 1
            raise HTTPException(status_code=401, detail="Invalid OTP code")

        # Mark OTP as consumed
        LAB_STATE["used_otps"].add(req.otp)
        return {"status": "success", "message": "OTP verified successfully"}
