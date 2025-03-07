import json
import logging
import requests

import import_declare_test
from solnlib import conf_manager, log
from splunklib import modularinput as smi
from sophos_client import SophosClient as sc
from solnlib.modular_input import checkpointer
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode

ADDON_NAME = "ta_sophos_cases_n_detections"

def logger_for_input(input_name: str) -> logging.Logger:
    """
    Creates and retrieves a logger instance for a specific input.

    Args:
        input_name (str): Name of the input for logging.
    
    Returns:
        logging.Logger: Logger instance for the given input.
    """
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")

def get_account_property(session_key: str, account_name: str, property_name: str):
    """
    Retrieves a specific property for a given Sophos account from the configuration manager.

    Args:
        session_key (str): Splunk session key for authentication.
        account_name (str): Name of the Sophos account.
        property_name (str): The specific property to retrieve.
    
    Returns:
        str: Value of the requested property.
    
    Raises:
        RuntimeError: If retrieving the property fails.
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            ADDON_NAME,
            realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-ta_sophos_cases_n_detections_account",
        )
        account_conf_file = cfm.get_conf("ta_sophos_cases_n_detections_account")
        return account_conf_file.get(account_name).get(property_name)
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve {property_name} for account {account_name}: {str(e)}")

def validate_input(definition: smi.ValidationDefinition):
    """
    Validation function for the modular input (currently unused).

    Args:
        definition (smi.ValidationDefinition): Validation definition.
    """
    return

def get_data_from_api(logger: logging.Logger, account_region: str, tenant_id: str, access_token: str, params: dict = None, sort_order: str = "asc"):
    """
    Retrieves data from the Sophos Central API with pagination and sorting by createdAt.

    Args:
        logger (logging.Logger): Logger instance for logging events.
        account_region (str): Sophos account region.
        tenant_id (str): Tenant ID in Sophos Central.
        access_token (str): Authentication token for the API.
        params (dict, optional): Additional query parameters.
        sort_order (str, optional): Sorting order, "asc" (oldest first) or "desc" (newest first).

    Returns:
        list: List of events retrieved from the API.
    """
    base_url = f'https://api-{account_region}.central.sophos.com/cases/v1/cases'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'X-Tenant-ID': tenant_id,
        'Accept': 'application/json'
    }

    all_items = []
    page = 1
    page_size = 50  # Default page size

    while True:
        params_with_pagination = params.copy() if params else {}
        params_with_pagination.update({
            "page": page,
            "size": page_size,
            "sort": f"createdAt:{sort_order}"
        })

        query_string = urlencode(params_with_pagination, doseq=True)
        api_url = f'{base_url}?{query_string}'

        try:
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            data = response.json()

            if "items" in data:
                all_items.extend(data["items"])

            if "pages" in data and page < data["pages"].get("total", page):
                page += 1
            else:
                break
        except requests.RequestException as e:
            logger.error(f'Error retrieving cases from API: {e}')
            break

    return all_items

def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    """
    Streams events from the Sophos Central API and writes them to Splunk.

    Args:
        inputs (smi.InputDefinition): Splunk input definition.
        event_writer (smi.EventWriter): Splunk event writer for ingesting data.
    """
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)

        try:
            session_key = inputs.metadata["session_key"]

            try:
                kvstore_checkpointer = checkpointer.KVStoreCheckpointer(
                    "sophos_cases_checkpointer",
                    session_key,
                    ADDON_NAME,
                )
            except Exception as e:
                logger.error(f"Error initializing KVStoreCheckpointer: {str(e)}")
                continue

            account_region = get_account_property(session_key, input_item.get("account"), "region")
            client_id = get_account_property(session_key, input_item.get("account"), "client_id")
            client_secret = get_account_property(session_key, input_item.get("account"), "client_secret")

            client = sc(logger, client_id, client_secret, session_key)
            checkpointer_key_name = normalized_input_name

            try:
                last_checkpoint = kvstore_checkpointer.get(checkpointer_key_name)
                last_created_at = last_checkpoint.get("createdAt", "1970-01-01T00:00:00.000Z") if last_checkpoint else "1970-01-01T00:00:00.000Z"
            except Exception as e:
                logger.warning(f"Error retrieving checkpoint: {str(e)}")

            params = {"createdAfter": last_created_at}
            data = get_data_from_api(logger, account_region, client.tenant_id, client.access_token, params)
            
            max_created_at = last_created_at
            sourcetype = "sophos:get:cases"

            if data:
                for line in data:
                    case_created_at = line.get("createdAt")
                    if case_created_at > max_created_at:
                        max_created_at = case_created_at
                    try:
                        event_writer.write_event(smi.Event(
                            data=json.dumps(line, ensure_ascii=False, default=str),
                            index=input_item.get("index"),
                            sourcetype=sourcetype,
                        ))
                    except Exception as e:
                        logger.error(f"Failed to write event: {str(e)}")

                try:
                    max_created_at_dt = datetime.strptime(max_created_at, "%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(milliseconds=1)
                    max_created_at = max_created_at_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"
                    kvstore_checkpointer.update(checkpointer_key_name, {"createdAt": max_created_at})
                except Exception as e:
                    logger.error(f"Failed to update checkpoint: {str(e)}")
        except Exception as e:
            logger.error(f"Exception raised while ingesting data: {str(e)}")
