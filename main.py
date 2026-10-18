
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import JSONResponse
import jwt

app = FastAPI(title="OAuth 2.0 / OIDC Token Verification Service")

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-c01ckbqq.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""


class VerifyRequest(BaseModel):
    token: str


@app.get("/")
def home():
    return {"message": "Token verification service is running"}


@app.post("/verify")
def verify_token(request: VerifyRequest):
    try:
        # Verify the signature, issuer, audience, and expiry.
        claims = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={
                "require": ["exp", "iss", "aud", "sub", "email"],
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )

        # Require the audience claim to equal the assigned value exactly.
        if claims["aud"] != AUDIENCE:
            return JSONResponse(
                status_code=401,
                content={"valid": False},
            )

        # Return the verified claims from the actual token.
        return {
            "valid": True,
            "email": claims["email"],
            "sub": claims["sub"],
            "aud": claims["aud"],
        }

    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError):
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )
