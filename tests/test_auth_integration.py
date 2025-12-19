import os
import pytest
import dotenv

from winix.auth import login, refresh

dotenv.load_dotenv()


pytestmark = pytest.mark.integration


@pytest.fixture
def credentials():
    username = os.environ.get("WINIX_USERNAME")
    password = os.environ.get("WINIX_PASSWORD")
    if not username or not password:
        pytest.skip("WINIX_USERNAME and WINIX_PASSWORD env vars required")
    return {"username": username, "password": password}


def test_login_and_refresh(credentials):
    auth = login(credentials["username"], credentials["password"])

    assert auth.user_id
    assert auth.access_token
    assert auth.refresh_token
    assert auth.id_token

    refreshed = refresh(auth.user_id, auth.refresh_token)

    assert refreshed.user_id == auth.user_id
    assert refreshed.access_token
    assert refreshed.access_token != auth.access_token
    assert refreshed.refresh_token == auth.refresh_token
    assert refreshed.id_token
