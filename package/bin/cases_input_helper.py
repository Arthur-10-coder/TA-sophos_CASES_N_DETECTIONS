import json
import logging
import requests

import import_declare_test
from solnlib import conf_manager, log
from splunklib import modularinput as smi
from sophos_client import SophosClient as sc
from solnlib.modular_input import checkpointer
from datetime import datetime, timezone
from urllib.parse import urlencode

ADDON_NAME = "ta_sophos_cases_n_detections"

def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")

def get_account_property(session_key: str, account_name: str, property_name: str):
    """Retreive a specific property for a given Sophos account."""
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
    return


def get_data_from_api(logger: logging.Logger, account_region: str, tenant_id: str, access_token: str, params: dict = None):
    logger.info("Retrieving data from the Sophos Central Cases API with pagination")
    base_url = f'https://api-{account_region}.central.sophos.com/cases/v1/cases'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'X-Tenant-ID': tenant_id,
        'Accept': 'application/json'
    }
    
    all_items = []
    page = 1
    page_size = 50  # Establecemos un tamaño de página razonable
    
    while True:
        params_with_pagination = params.copy() if params else {}
        params_with_pagination.update({"page": page, "size": page_size})
        
        query_string = urlencode(params_with_pagination, doseq=True)
        api_url = f'{base_url}?{query_string}'
        
        try:
            logger.info(f"Fetching page {page} from {api_url}")
            response = requests.get(api_url, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            if "items" in data:
                all_items.extend(data["items"])
            
            # Verificar si hay más páginas
            if "pages" in data and page < data["pages"].get("total", page):
                page += 1  # Incrementamos el número de página
            else:
                break  # Si no hay más páginas, terminamos el bucle
        except requests.RequestException as e:
            logger.error(f'Error retrieving cases: {e}')
            break
    
    return all_items


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    # inputs.inputs is a Python dictionary object like:
    # {
    #   "cases_input://<input_name>": {
    #     "account": "<account_name>",
    #     "disabled": "0",
    #     "host": "$decideOnStartup",
    #     "index": "<index_name>",
    #     "interval": "<interval_value>",
    #     "python.version": "python3",
    #   },
    # }
    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]
        logger = logger_for_input(normalized_input_name)
        try:
            session_key = inputs.metadata["session_key"]
                        # Initialize KV store checkpointer
            try:
                kvstore_checkpointer = checkpointer.KVStoreCheckpointer(
                    "conversations_metrics_checkpointer",
                    session_key,
                    ADDON_NAME,
                )
            except Exception as e:
                logger.error(f"Error initializing KVStoreCheckpointer: {str(e)}")
                continue  # Skip this input if checkpointer fails

            
            log_level = conf_manager.get_log_level(
                logger=logger,
                session_key=session_key,
                app_name=ADDON_NAME,
                conf_name="ta_sophos_cases_n_detections_settings",
            )
            logger.setLevel(log_level)
            log.modular_input_start(logger, normalized_input_name)
            
            account_region = get_account_property(session_key, input_item.get("account"), "region")
            client_id = get_account_property(session_key, input_item.get("account"), "client_id")
            client_secret = get_account_property(session_key, input_item.get("account"), "client_secret")
            logger.info(f"WORKING1 {account_region} {client_id} {client_secret}")
            client = sc(logger,client_id,client_secret)
            logger.info(f"WORKING2 {client.__dict__}")

            checkpointer_key_name = normalized_input_name
            logger.info(f"WORKING3 {checkpointer_key_name}")

                       # Retrieve the last checkpoint or set it to 1970-01-01 if it doesn't exist
            try:
                #kvstore_checkpointer.get(checkpointer_key_name) or 
                current_checkpoint =  datetime(1970, 1, 1).timestamp()
            except Exception as e:
                logger.warning(f"Error retrieving checkpoint: {str(e)}")
            
            start_time = datetime.fromtimestamp(current_checkpoint, tz=timezone.utc)

            params = {
                "createdAfter" : f"{start_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z"
            }
            
            logger.info(f"WORKING5 Calling API {params}")

            data = get_data_from_api(logger, account_region, client.tenant_id, client.access_token, params)
            
            logger.info(f"WORKING6 DATA RETREIVED {data}")

            sourcetype = "sophos:get:cases"
            if data:
                for line in data:
                    try:
                        event_writer.write_event(
                            smi.Event(
                                data=json.dumps(line, ensure_ascii=False, default=str),
                                index=input_item.get("index"),
                                sourcetype=sourcetype,
                            )
                    )
                    except Exception as e:
                        logger.error(f"Failed to write event: {str(e)}")

                # Only update checkpoint if data was processed
                try:
                    kvstore_checkpointer.update(checkpointer_key_name, datetime.now(timezone.utc).timestamp())
                except Exception as e:
                    logger.error(f"Failed to update checkpoint: {str(e)}")
            log.events_ingested(
                logger,
                input_name,
                sourcetype,
                len(data),
                input_item.get("index"),
                account=input_item.get("account"),
            )
            log.modular_input_end(logger, normalized_input_name)
        except Exception as e:
            log.log_exception(logger, e, "my custom error type", msg_before="Exception raised while ingesting data for demo_input: ")
