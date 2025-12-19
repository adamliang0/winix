from unittest.mock import MagicMock, patch
import pytest

from winix.auth import (
    WinixAuthResponse,
    login,
    refresh,
    _boto_client,
    _secret_hash,
    COGNITO_APP_CLIENT_ID,
    COGNITO_CLIENT_SECRET_KEY,
    COGNITO_USER_POOL_ID,
    COGNITO_REGION,
)


@pytest.fixture
def mock_auth_result():
    return {
        "AuthenticationResult": {
            "AccessToken": "test-access-token",
            "RefreshToken": "test-refresh-token",
            "IdToken": "test-id-token",
        }
    }


@pytest.fixture
def mock_refresh_result():
    return {
        "AuthenticationResult": {
            "AccessToken": "new-access-token",
            "IdToken": "new-id-token",
        }
    }


class TestWinixAuthResponse:
    def test_dataclass_fields(self):
        resp = WinixAuthResponse(
            user_id="uid-123",
            access_token="access",
            refresh_token="refresh",
            id_token="id",
        )
        assert resp.user_id == "uid-123"
        assert resp.access_token == "access"
        assert resp.refresh_token == "refresh"
        assert resp.id_token == "id"


class TestLogin:
    @patch("jose.jwt.get_unverified_claims")
    @patch("winix.auth.Cognito")
    def test_login_default_params(self, mock_cognito_class, mock_jwt_claims):
        mock_user = MagicMock()
        mock_user.access_token = "test-access-token"
        mock_user.refresh_token = "test-refresh-token"
        mock_user.id_token = "test-id-token"
        mock_cognito_class.return_value = mock_user
        mock_jwt_claims.return_value = {"sub": "user-sub-123"}

        result = login("user@test.com", "password123")

        mock_cognito_class.assert_called_once()
        call_kwargs = mock_cognito_class.call_args
        assert call_kwargs[0][0] == COGNITO_USER_POOL_ID
        assert call_kwargs[0][1] == COGNITO_APP_CLIENT_ID
        assert call_kwargs[1]["client_secret"] == COGNITO_CLIENT_SECRET_KEY
        assert call_kwargs[1]["username"] == "user@test.com"

        mock_user.authenticate.assert_called_once_with(password="password123")
        assert result.user_id == "user-sub-123"
        assert result.access_token == "test-access-token"
        assert result.refresh_token == "test-refresh-token"
        assert result.id_token == "test-id-token"

    @patch("jose.jwt.get_unverified_claims")
    @patch("winix.auth.Cognito")
    def test_login_custom_params(self, mock_cognito_class, mock_jwt_claims):
        mock_user = MagicMock()
        mock_user.access_token = "test-access-token"
        mock_user.refresh_token = "test-refresh-token"
        mock_user.id_token = "test-id-token"
        mock_cognito_class.return_value = mock_user
        mock_jwt_claims.return_value = {"sub": "custom-sub"}

        result = login(
            "user@test.com",
            "pass",
            pool_id="custom-pool",
            client_id="custom-client",
            client_secret="custom-secret",
        )

        call_kwargs = mock_cognito_class.call_args
        assert call_kwargs[0][0] == "custom-pool"
        assert call_kwargs[0][1] == "custom-client"
        assert call_kwargs[1]["client_secret"] == "custom-secret"
        assert result.user_id == "custom-sub"

    @patch("winix.auth.Cognito")
    def test_login_missing_tokens_raises(self, mock_cognito_class):
        mock_user = MagicMock()
        mock_user.access_token = None
        mock_user.refresh_token = None
        mock_user.id_token = None
        mock_cognito_class.return_value = mock_user

        with pytest.raises(RuntimeError, match="missing tokens"):
            login("user@test.com", "password123")


class TestRefresh:
    @patch("winix.auth._boto_client")
    def test_refresh_default_params(self, mock_boto, mock_refresh_result):
        mock_client = MagicMock()
        mock_client.initiate_auth.return_value = mock_refresh_result
        mock_boto.return_value = mock_client

        result = refresh("user-id-123", "my-refresh-token")

        mock_client.initiate_auth.assert_called_once()
        call_kwargs = mock_client.initiate_auth.call_args[1]
        assert call_kwargs["ClientId"] == COGNITO_APP_CLIENT_ID
        assert call_kwargs["AuthFlow"] == "REFRESH_TOKEN"
        assert call_kwargs["AuthParameters"]["REFRESH_TOKEN"] == "my-refresh-token"

        assert result.user_id == "user-id-123"
        assert result.access_token == "new-access-token"
        assert result.refresh_token == "my-refresh-token"
        assert result.id_token == "new-id-token"

    @patch("winix.auth._boto_client")
    def test_refresh_custom_params(self, mock_boto, mock_refresh_result):
        mock_client = MagicMock()
        mock_client.initiate_auth.return_value = mock_refresh_result
        mock_boto.return_value = mock_client

        result = refresh(
            "uid",
            "token",
            client_id="custom-client",
            client_secret="custom-secret",
            pool_region="ap-south-1",
        )

        call_kwargs = mock_client.initiate_auth.call_args[1]
        assert call_kwargs["ClientId"] == "custom-client"
        mock_boto.assert_called_once_with("ap-south-1")


class TestSecretHash:
    def test_secret_hash_computation(self):
        result = _secret_hash("testuser", "testclient", "testsecret")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_secret_hash_deterministic(self):
        h1 = _secret_hash("user", "client", "secret")
        h2 = _secret_hash("user", "client", "secret")
        assert h1 == h2

    def test_secret_hash_differs_for_different_inputs(self):
        h1 = _secret_hash("user1", "client", "secret")
        h2 = _secret_hash("user2", "client", "secret")
        assert h1 != h2


class TestBotoClient:
    @patch("winix.auth.boto3")
    def test_default_region(self, mock_boto3):
        _boto_client(None)

        mock_boto3.client.assert_called_once()
        call_kwargs = mock_boto3.client.call_args
        assert call_kwargs[0][0] == "cognito-idp"
        assert call_kwargs[1]["region_name"] == COGNITO_REGION

    @patch("winix.auth.boto3")
    def test_custom_region(self, mock_boto3):
        _boto_client("eu-central-1")

        call_kwargs = mock_boto3.client.call_args
        assert call_kwargs[1]["region_name"] == "eu-central-1"
