import logging
import requests
import time
from solnlib.modular_input import checkpointer

ADDON_NAME = "ta_sophos_cases_n_detections"

class SophosClient:
    _instance = None  # Singleton instance dentro del mismo proceso

    def __new__(cls, logger: logging.Logger, client_id: str, client_secret: str, session_key: str):
        if cls._instance is None:
            cls._instance = super(SophosClient, cls).__new__(cls)
            cls._instance._init_client(logger, client_id, client_secret, session_key)
            logger.info(f"WORKING_-1 CREATING INSTANCE OF SOPHOS CLIENT {SophosClient._instance}")
        return cls._instance

    def _init_client(self, logger: logging.Logger, client_id: str, client_secret: str, session_key: str):
        self._client_id = client_id
        self._client_secret = client_secret
        self.logger = logger
        self.session_key = session_key
        self.access_token = None
        self.refresh_token = None
        self.tenant_id = None
        self.token_expiry = 0
        self.kv_checkpointer = checkpointer.KVStoreCheckpointer("sophos_token_cache", session_key, ADDON_NAME)

        self.logger.info(f"WORKING_0 Initializing SophosClient instance. {self.__dict__}")
        self._load_cached_token()
        self.authenticate()
        self.retrieve_tenant_id()

    def get_client_id(self):
        """Devuelve el Client ID de la configuración."""
        return self._client_id

    def get_client_secret(self):
        """Devuelve el Client Secret de la configuración."""
        return self._client_secret


    def _load_cached_token(self):
        """Carga el token desde KV Store. Si no existe, autentica y lo crea."""
        self.logger.info("WORKING_1 Checking for cached OAuth2 token in KV Store.")

        try:
            cache = self.kv_checkpointer.get("sophos_token")

            if cache is None:
                self.logger.info("WORKING_2 No cached token found in KV Store (first execution), calling authenticate().")
                return  # Salimos ya que authenticate() maneja el almacenamiento del token

            # Extraer datos del cache si existen
            self.access_token = cache.get("access_token")
            self.refresh_token = cache.get("refresh_token")
            self.tenant_id = cache.get("tenant_id")
            self.token_expiry = cache.get("token_expiry", 0)

            self.logger.info("WORKING_3 Cached token found and loaded successfully.")

        except Exception as e:
            self.logger.error(f"WORKING_4 Error retrieving cached token from KV Store: {e}")
            self.logger.info("WORKING_5 Calling authenticate() as a fallback.")
            self.authenticate()  # 🔹 Si hay un error, intentamos autenticar de nuevo.


    def authenticate(self):
        """Obtiene un nuevo token si ha expirado o usa el cacheado."""
        if self.access_token and time.time() < self.token_expiry - 60:
            self.logger.info("WORKING_4 Using cached access token.")
            return

        try:
            self.logger.info("WORKING_5 Requesting new OAuth2 token from Sophos.")
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
            self.logger.error(f'WORKING_7 HTTP request error during authentication: {e}')

    def _store_token(self, token_response):
        """Almacena token en KV Store para futuras ejecuciones."""
        self.access_token = token_response.get('access_token')
        self.refresh_token = token_response.get('refresh_token')
        self.token_expiry = time.time() + token_response.get('expires_in', 3600)

        self.logger.info("WORKING_8 Storing token in KV Store.")
        self.kv_checkpointer.update("sophos_token", {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_expiry": self.token_expiry
        })

    def retrieve_tenant_id(self):
        """Obtiene el Tenant ID de Sophos si no está almacenado en KV Store."""
        if self.tenant_id:
            self.logger.info("WORKING_9 Using cached tenant ID.")
            return

        try:
            self.logger.info("WORKING_10 Requesting tenant ID from Sophos API.")
            whoami_url = 'https://api.central.sophos.com/whoami/v1'
            headers = {'Authorization': f'Bearer {self.access_token}'}
            response = requests.get(whoami_url, headers=headers)
            response.raise_for_status()
            self.tenant_id = response.json().get('id')

            self.logger.info("WORKING_11 Tenant ID obtained, storing in KV Store.")
            self.kv_checkpointer.update("sophos_token", {
                "access_token": self.access_token,
                "refresh_token": self.refresh_token,
                "tenant_id": self.tenant_id,
                "token_expiry": self.token_expiry
            })

        except requests.RequestException as e:
            self.logger.error(f'WORKING_12 HTTP request error during tenant ID retrieval: {e}')

