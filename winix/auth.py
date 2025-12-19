from dataclasses import dataclass
import base64
import hashlib
import hmac

import boto3
from botocore import UNSIGNED
from botocore.client import Config
from pycognito import Cognito

COGNITO_APP_CLIENT_ID = "14og512b9u20b8vrdm55d8empi"
COGNITO_CLIENT_SECRET_KEY = "k554d4pvgf2n0chbhgtmbe4q0ul4a9flp3pcl6a47ch6rripvvr"
COGNITO_USER_POOL_ID = "us-east-1_Ofd50EosD"
COGNITO_REGION = "us-east-1"


@dataclass
class WinixAuthResponse:
    user_id: str
    access_token: str
    refresh_token: str
    id_token: str


def login(username: str, password: str, **kwargs) -> WinixAuthResponse:
    """Generate fresh credentials via Cognito SRP auth."""
    from jose import jwt

    pool_id = kwargs.get("pool_id", COGNITO_USER_POOL_ID)
    client_id = kwargs.get("client_id", COGNITO_APP_CLIENT_ID)
    client_secret = kwargs.get("client_secret", COGNITO_CLIENT_SECRET_KEY)

    user = Cognito(
        pool_id,
        client_id,
        client_secret=client_secret,
        username=username,
        botocore_config=Config(signature_version=UNSIGNED),
    )
    user.authenticate(password=password)

    if not user.access_token or not user.refresh_token or not user.id_token:
        raise RuntimeError("Authentication failed: missing tokens")

    return WinixAuthResponse(
        user_id=jwt.get_unverified_claims(user.access_token)["sub"],
        access_token=user.access_token,
        refresh_token=user.refresh_token,
        id_token=user.id_token,
    )


def refresh(user_id: str, refresh_token: str, **kwargs) -> WinixAuthResponse:
    """Refresh tokens using refresh_token."""
    client_id = kwargs.get("client_id", COGNITO_APP_CLIENT_ID)
    client_secret = kwargs.get("client_secret", COGNITO_CLIENT_SECRET_KEY)

    auth_params = {
        "REFRESH_TOKEN": refresh_token,
        "SECRET_HASH": _secret_hash(user_id, client_id, client_secret),
    }

    resp = _boto_client(kwargs.get("pool_region")).initiate_auth(
        ClientId=client_id,
        AuthFlow="REFRESH_TOKEN",
        AuthParameters=auth_params,
    )

    return WinixAuthResponse(
        user_id=user_id,
        access_token=resp["AuthenticationResult"]["AccessToken"],
        refresh_token=refresh_token,
        id_token=resp["AuthenticationResult"]["IdToken"],
    )


def _secret_hash(username: str, client_id: str, client_secret: str) -> str:
    """Compute Cognito secret hash (HMAC-SHA256)."""
    msg = (username + client_id).encode()
    key = client_secret.encode()
    return base64.b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode()


def _boto_client(region):
    """Get an uncredentialed boto cognito-idp client."""
    return boto3.client(
        "cognito-idp",
        config=Config(signature_version=UNSIGNED),
        region_name=region or COGNITO_REGION,
    )
