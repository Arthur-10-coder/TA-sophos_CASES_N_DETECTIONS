import logging
import requests

class SophosClient:
    """
    A client to interact with the Sophos API, handling authentication and tenant identification.

    Attributes:
        client_id (str): Sophos API client ID.
        client_secret (str): Sophos API client secret.
        logger (logging.Logger): Logger instance for logging errors and information.
        access_token (str): Bearer token for API authentication.
        tenant_id (str): Identifier for the Sophos tenant.
    """

    def __init__(self, client_id: str, client_secret: str, logger: logging.Logger):
        """
        Initialize the SophosClient with client credentials and a logger.

        Args:
            client_id (str): Sophos API client ID.
            client_secret (str): Sophos API client secret.
            logger (logging.Logger): Logger instance for logging errors and information.
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self.logger = logger
        self.access_token = None
        self.tenant_id = None
        self.authenticate()
        self.retrieve_tenant_id()

    def get_client_id(self):
        return self._client_id
 
    def get_client_secret(self):
        return self._client_secret

    def authenticate(self):
        """
        Obtain an access token using the client credentials.
        """
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
            self.access_token = response.json().get('access_token')
            if not self.access_token:
                raise RuntimeError('Failed to obtain access token.')
        except requests.RequestException as e:
            self.logger.error(f'HTTP request error during authentication: {e}')
        except Exception as e:
            self.logger.error(f'Unexpected error during authentication: {e}')

    def retrieve_tenant_id(self):
        """
        Retrieve the tenant ID using the access token.
        """
        if not self.access_token:
            self.logger.error('Access token is not available. Cannot retrieve tenant ID.')
            return
        try:
            whoami_url = 'https://api.central.sophos.com/whoami/v1'
            headers = {'Authorization': f'Bearer {self.access_token}'}
            response = requests.get(whoami_url, headers=headers)
            response.raise_for_status()
            self.tenant_id = response.json().get('id')
            if not self.tenant_id:
                raise RuntimeError('Failed to obtain tenant ID.')
        except requests.RequestException as e:
            self.logger.error(f'HTTP request error during tenant ID retrieval: {e}')
        except Exception as e:
            self.logger.error(f'Unexpected error during tenant ID retrieval: {e}')
