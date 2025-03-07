import logging
import requests
import time
from solnlib.modular_input import checkpointer

ADDON_NAME = "ta_sophos_cases_n_detections"

class SophosClient:
    """
    Singleton class for handling authentication and API interactions with Sophos Central.
    Manages OAuth2 tokens and tenant ID retrieval.
    """
    _instance = None  # Singleton instance within the same process

    def __new__(cls, logger: logging.Logger, client_id: str, client_secret: str, session_key: str):
        """
        Creates or retrieves a singleton instance of SophosClient.
        
        Args:
            logger (logging.Logger): Logger instance for logging events.
            client_id (str): OAuth2 Client ID.
            client_secret (str): OAuth2 Client Secret.
            session_key (str): Splunk session key for authentication.

        Returns:
            SophosClient: Singleton instance of SophosClient.
        """
        if cls._instance is None:
            cls._instance = super(SophosClient, cls).__new__(cls)
            cls._instance._init_client(logger, client_id, client_secret, session_key)
        return cls._instance

    def _init_client(self, logger: logging.Logger, client_id: str, client_secret: str, session_key: str):
        """
        Initializes the SophosClient instance with credentials and retrieves cached tokens if available.

        Args:
            logger (logging.Logger): Logger instance.
            client_id (str): OAuth2 Client ID.
            client_secret (str): OAuth2 Client Secret.
            session_key (str): Splunk session key.
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self.logger = logger
        self.session_key = session_key
        self.access_token = None
        self.refresh_token = None
        self.tenant_id = None
        self.token_expiry = 0
        self.kv_checkpointer = checkpointer.KVStoreCheckpointer("sophos_token_cache", session_key, ADDON_NAME)

        self._load_cached_token()
        self.authenticate()
        self.retrieve_tenant_id()

    def get_client_id(self):
        """
        Returns the configured Client ID.

        Returns:
            str: Client ID.
        """
        return self._client_id

    def get_client_secret(self):
        """
        Returns the configured Client Secret.

        Returns:
            str: Client Secret.
        """
        return self._client_secret

    def _load_cached_token(self):
        """
        Loads the OAuth2 token from KV Store if available, otherwise triggers authentication.
        """
        try:
            cache = self.kv_checkpointer.get("sophos_token")
            if cache is None:
                return
            self.access_token = cache.get("access_token")
            self.refresh_token = cache.get("refresh_token")
            self.tenant_id = cache.get("tenant_id")
            self.token_expiry = cache.get("token_expiry", 0)
        except Exception as e:
            self.logger.error(f"Error retrieving cached token from KV Store: {e}")
            self.authenticate()

    def authenticate(self):
        """
        Authenticates with Sophos Central and retrieves a new OAuth2 token if expired or unavailable.
        """
        if self.access_token and time.time() < self.token_expiry - 60:
            return

        try:
            auth_url = 'https://id.sophos.com/api/v2/oauth2/token'
            auth_data = {
                'grant_type': 'client_credentials',
                'client_id': self.get_client_id(),
                'client_secret': self.get_client_secret(),
                'scope': 'token'
            }
            response = requests.post(auth_url, data=auth_data)
            response.raise_for_status()
            token_response = response.json()
            self._store_token(token_response)
        except requests.RequestException as e:
            self.logger.error(f'HTTP request error during authentication: {e}')

    def _store_token(self, token_response):
        """
        Stores the OAuth2 token in KV Store for future use.

        Args:
            token_response (dict): Token response from the authentication request.
        """
        self.access_token = token_response.get('access_token')
        self.refresh_token = token_response.get('refresh_token')
        self.token_expiry = time.time() + token_response.get('expires_in', 3600)

        self.kv_checkpointer.update("sophos_token", {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_expiry": self.token_expiry
        })

    def retrieve_tenant_id(self):
        """
        Retrieves the Tenant ID from Sophos Central if not already cached.
        """
        if self.tenant_id:
            return

        try:
            whoami_url = 'https://api.central.sophos.com/whoami/v1'
            headers = {'Authorization': f'Bearer {self.access_token}'}
            response = requests.get(whoami_url, headers=headers)
            response.raise_for_status()
            self.tenant_id = response.json().get('id')

            self.kv_checkpointer.update("sophos_token", {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "tenant_id": self.tenant_id,
                "token_expiry": self.token_expiry
            })
        except requests.RequestException as e:
            self.logger.error(f'HTTP request error during tenant ID retrieval: {e}')
