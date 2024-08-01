import asyncio
import atexit
import threading
import time
import requests
import jwt
import urllib.parse as urlparse

GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"


class SingletonMetaclass(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


# Singleton class to manage authentication
class AuthService(metaclass=SingletonMetaclass):
    def __init__(
        self, initial_token, client_id, client_secret, oidc_url, audience=None
    ):
        self.oidc_url = oidc_url
        self.audience = audience
        self.initial_client = AuthClient(client_id, client_secret, oidc_url)
        self._access_token, self._refresh_token = self._exchange_token(
            self.initial_client,
            initial_token,
            ["offline_access", "ga4gh_passport_v1", "openid"],
        )
        self.client = self._get_dynreg_client(self.initial_client, oidc_url, audience)

        self._access_token, self._refresh_token = self._exchange_token(
            self.client,
            self.access_token,
            ["offline_access", "ga4gh_passport_v1", "openid"],
            audience,
        )

        refresh_thread = threading.Thread(
            target=self._run_periodic_refresh, daemon=True
        )
        refresh_thread.start()

        def cleanup():
            self.client.deregister_self()

        atexit.register(cleanup)

    def refresh_token(self):
        self._access_token, self._refresh_token = self.client.refresh_access_token(
            self._refresh_token
        )

    def _run_periodic_refresh(self):
        while True:
            self.refresh_token()
            time.sleep(10)

    @property
    def access_token(self):
        # Should always return a valid access token
        return self._access_token

    def _exchange_token(self, client, token, scopes, audience=None) -> tuple[str, str]:
        if not client.is_token_valid(token):
            raise Exception("Initial token is not valid")

        exchange_result = client.exchange_access_token(token, scopes, audience)

        access_token = exchange_result["access_token"]
        refresh_token = exchange_result["refresh_token"]

        return access_token, refresh_token

    def _get_dynreg_client(self, initial_client, oidc_url, audience):
        dynreg_client_result = initial_client.register_client(
            "run",
            [audience],
            [
                "offline_access",
                "ga4gh_passport_v1",
                "openid",
                "client_dynamic_deregistration",
            ],
        )

        dynreg_client = AuthClient(
            dynreg_client_result["client_id"],
            dynreg_client_result["client_secret"],
            oidc_url,
        )

        return dynreg_client


class AuthClient:
    def __init__(self, client_id, client_secret, oidc_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.oidc_url = oidc_url if not oidc_url.endswith("/") else oidc_url[:-1]

        self.introspect_url = self.oidc_url + "/introspect"
        self.token_url = self.oidc_url + "/token"
        self.register_url = self.oidc_url + "/register"
        self.jwks_url = self.oidc_url + "/jwk"

        self.basic_auth = requests.auth.HTTPBasicAuth(
            self.client_id, self.client_secret
        )

    def is_token_expired(self, token, time_offset=0):
        jwks_client = jwt.PyJWKClient(self.jwks_url)
        header = jwt.get_unverified_header(token)
        key = jwks_client.get_signing_key(header["kid"]).key

        try:
            data = jwt.decode(
                token, key, [header["alg"]], options={"verify_aud": False}
            )
            if data["exp"] - time_offset < 0:
                return True
        except jwt.ExpiredSignatureError:
            return True

        return False

    def is_token_valid(self, token):
        body = {"token": token}

        response = requests.post(self.introspect_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to validate the access token: " + response.text)

        token_info = response.json()

        if token_info["active"]:
            return True

        return False

    def get_new_token(self, scopes, audience=None):
        body = {
            "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS,
            "scope": " ".join(scopes),
        }

        if audience:
            body["audience"] = audience

        response = requests.post(self.token_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to get a new access token: " + response.text)

        return response.json()

    def exchange_access_token(self, token, scopes, audience=None):
        body = {
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": " ".join(scopes),
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        }

        if audience:
            body["audience"] = audience

        response = requests.post(self.token_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to exchange access token: " + response.text)

        return response.json()

    def refresh_access_token(self, refresh_token):
        body = {
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

        response = requests.post(self.token_url, body, auth=self.basic_auth)

        if response.status_code != 200:
            raise Exception("Failed to refresh access token: " + response.text)

        response_data = response.json()

        return response_data["access_token"], response_data["refresh_token"]

    def register_client(
        self,
        client_name,
        resource_ids,
        scopes,
        access_token_validity_seconds=600,
        refresh_token_validity_seconds=3600,
    ):
        new_token_response = self.get_new_token(["client_dynamic_registration"])
        access_token = new_token_response["access_token"]

        body = {
            "client_name": client_name,
            "grant_types": [
                "urn:ietf:params:oauth:grant-type:token-exchange",
                "refresh_token",
                "client_credentials",
            ],
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": scopes,
            "resources": resource_ids,
            "access_token_validity_seconds": access_token_validity_seconds,
            "refresh_token_validity_seconds": refresh_token_validity_seconds,
        }

        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.post(self.register_url, json=body, headers=headers)

        if response.status_code != 201:
            raise Exception("Failed to register a new client: " + response.text)

        response_data = response.json()

        return {
            "client_id": response_data["client_id"],
            "client_secret": response_data["client_secret"],
        }

    def deregister_self(self):
        new_token_response = self.get_new_token(["client_dynamic_deregistration"])
        access_token = new_token_response["access_token"]

        headers = {"Authorization": f"Bearer {access_token}"}
        base_register_url = (
            self.register_url
            if self.register_url.endswith("/")
            else self.register_url + "/"
        )
        url = urlparse.urljoin(base_register_url, self.client_id)
        response = requests.delete(url, headers=headers)

        if response.status_code != 204:
            raise Exception("Failed to deregister the client: " + response.text)
