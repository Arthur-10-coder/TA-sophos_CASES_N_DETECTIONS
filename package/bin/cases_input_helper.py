import json
import logging
import requests

import import_declare_test
from solnlib import conf_manager, log
from splunklib import modularinput as smi
from sophos_client import SophosClient as sc

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

def get_data_from_api(logger: logging.Logger, account_region: str, tenant_id: str, access_token: str):
    logger.info("Retrieving data from the Sophos Central Cases API")
    api_url = f'https://api-{account_region}.central.sophos.com/cases/v1/cases'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'X-Tenant-ID': tenant_id
    }
    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.RequestException as e:
        logger.error(f'Error retrieving cases: {e}')
        return None

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
            
            client = sc(logger,client_id,client_secret)

            data = get_data_from_api(logger ,account_region, client.tenant_id, client.access_token)
            sourcetype = "sophos:get:cases"
            for line in data:
                event_writer.write_event(
                    smi.Event(
                        data=json.dumps(line, ensure_ascii=False, default=str),
                        index=input_item.get("index"),
                        sourcetype=sourcetype,
                    )
                )
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
