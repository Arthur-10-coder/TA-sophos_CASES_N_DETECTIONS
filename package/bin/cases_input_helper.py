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
    """Validation function for the modular input (currently unused)."""
    return

def get_data_from_api(logger: logging.Logger, account_region: str, tenant_id: str, access_token: str, params: dict = None, sort_order: str = "asc"):
    """
    Recupera datos de la API de Sophos Central con paginación y ordenamiento por createdAt.

    Args:
        logger (logging.Logger): Instancia del logger para registrar eventos.
        account_region (str): Región de la cuenta de Sophos.
        tenant_id (str): ID del tenant en Sophos Central.
        access_token (str): Token de acceso para autenticación en la API.
        params (dict, opcional): Parámetros adicionales para la consulta.
        sort_order (str, opcional): Orden de los resultados, "asc" (antiguos primero) o "desc" (nuevos primero). 

    Returns:
        list: Lista de eventos recuperados de la API.
    """
    logger.info(f"WORKING_0 Retrieving data from the Sophos Central Cases API with pagination (order: {sort_order})")
    
    base_url = f'https://api-{account_region}.central.sophos.com/cases/v1/cases'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'X-Tenant-ID': tenant_id,
        'Accept': 'application/json'
    }

    all_items = []
    page = 1
    page_size = 50  # Tamaño de página por defecto

    while True:
        params_with_pagination = params.copy() if params else {}
        params_with_pagination.update({
            "page": page,
            "size": page_size,
            "sort": f"createdAt:{sort_order}"  # 🔹 Se agrega el ordenamiento por `createdAt`
        })

        query_string = urlencode(params_with_pagination, doseq=True)
        api_url = f'{base_url}?{query_string}'

        try:
            logger.info(f"WORKING_1 Fetching page {page} from {api_url}")
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
            logger.error(f'WORKING_2 Error retrieving cases: {e}')
            break

    logger.info(f"WORKING_3 Retrieved {len(all_items)} items from API")
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

            # Inicializar KV Store Checkpointer
            try:
                kvstore_checkpointer = checkpointer.KVStoreCheckpointer(
                    "sophos_cases_checkpointer",
                    session_key,
                    ADDON_NAME,
                )
                logger.info("WORKING_1 Initialized KVStoreCheckpointer.")
            except Exception as e:
                logger.error(f"WORKING_2 Error initializing KVStoreCheckpointer: {str(e)}")
                continue

            account_region = get_account_property(session_key, input_item.get("account"), "region")
            client_id = get_account_property(session_key, input_item.get("account"), "client_id")
            client_secret = get_account_property(session_key, input_item.get("account"), "client_secret")

            logger.info("WORKING_3 Retrieving account credentials.")
            
            client = sc(logger, client_id, client_secret, session_key)
            logger.info("WORKING_4 SophosClient instance obtained.")

            checkpointer_key_name = normalized_input_name

            # Obtener el último checkpoint basado solo en createdAt
            try:
                last_checkpoint = kvstore_checkpointer.get(checkpointer_key_name)
                if last_checkpoint:
                    last_created_at = last_checkpoint.get("createdAt", "1970-01-01T00:00:00.000Z")
                else:
                    last_created_at = "1970-01-01T00:00:00.000Z"

                logger.info(f"WORKING_5 Retrieved checkpoint: createdAt={last_created_at}")

            except Exception as e:
                logger.warning(f"WORKING_6 Error retrieving checkpoint: {str(e)}")

            # Consultar la API usando createdAfter
            params = {"createdAfter": last_created_at}
            logger.info(f"WORKING_7 Constructed API query parameters: {params}")

            # Obtener los datos desde la API con paginación
            data = get_data_from_api(logger, account_region, client.tenant_id, client.access_token, params)
            logger.info(f"WORKING_8 Data retrieved from Sophos API. {data}")

            # Variable para actualizar el checkpoint
            max_created_at = last_created_at

            sourcetype = "sophos:get:cases"

            if data:
                for line in data:
                    case_created_at = line.get("createdAt")

                    # Actualizar el máximo createdAt para el checkpoint
                    if case_created_at > max_created_at:
                        max_created_at = case_created_at

                    try:
                        event_writer.write_event(smi.Event(
                            data=json.dumps(line, ensure_ascii=False, default=str),
                            index=input_item.get("index"),
                            sourcetype=sourcetype,
                        ))
                    except Exception as e:
                        logger.error(f"WORKING_9 Failed to write event: {str(e)}")

                # Guardar el checkpoint con el nuevo createdAt
                try:
                    # Convertir `max_created_at` de string a datetime
                    max_created_at_dt = datetime.strptime(max_created_at, "%Y-%m-%dT%H:%M:%S.%fZ")

                    # Sumar 1 milésima de segundo
                    max_created_at_dt += timedelta(milliseconds=1)

                    # Convertir de nuevo a string en formato ISO 8601
                    max_created_at = max_created_at_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3] + "Z"

                    # Guardar en KV Store
                    kvstore_checkpointer.update(checkpointer_key_name, {
                        "createdAt": max_created_at
                    })
                    logger.info(f"WORKING_10 Updated checkpoint: createdAt={max_created_at}")

                except Exception as e:
                    logger.error(f"WORKING_11 Failed to update checkpoint: {str(e)}")

            log.events_ingested(logger, input_name, sourcetype, len(data), input_item.get("index"), account=input_item.get("account"))
            log.modular_input_end(logger, normalized_input_name)

        except Exception as e:
            log.log_exception(logger, e, "my custom error type", msg_before="WORKING_12 Exception raised while ingesting data for cases_input.")
