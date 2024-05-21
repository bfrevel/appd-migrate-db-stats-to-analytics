import configparser
from pathlib import Path
import logging
import queue
import threading
import requests
import time
from datetime import datetime, timedelta, timezone
from cryptography.fernet import Fernet
import schedule


logging.getLogger().setLevel(logging.INFO)
FORMAT = "%(asctime)s %(module)s %(levelname)s %(message)s"
logging.basicConfig(format=FORMAT)


def read_passwd_property(property: str, key: Fernet = None):
    if property.startswith("encrypted:"):
        if key is None:
            logging.fatal(
                f"File config.key is not available but property {property} is encrypted"
            )
            exit(1)
        else:
            return key.decrypt(property.split(":")[1]).decode("utf-8")
    else:
        return property


def load_config():
    path = Path("./config.key")
    if path.is_file():
        with open("config.key", "rb") as config_key:
            line = config_key.read()
        key = Fernet(line)
    else:
        key = None

    config_parser = configparser.ConfigParser()
    config_parser.read("config.ini")

    config = {
        "controller_api": {
            "url": config_parser.get("controller-api", "url"),
            "client_id": config_parser.get("controller-api", "client_id"),
            "client_secret": read_passwd_property(
                config_parser.get("controller-api", "client_secret"), key
            ),
            "ssl_verify": config_parser.get(
                "controller-api", "ssl_verify", fallback=None
            ),
        },
        "database_ui_api": {
            "db_server_id": config_parser.getint("database-ui-api", "db_server_id"),
            "db_config_id": config_parser.getint("database-ui-api", "db_config_id"),
            "db_config_size": config_parser.getint("database-ui-api", "db_config_size"),
        },
        "events_service_api": {
            "url": config_parser.get("events-service-api", "url"),
            "account_name": config_parser.get("events-service-api", "account_name"),
            "api_key": read_passwd_property(
                config_parser.get("events-service-api", "api_key"), key
            ),
            "ssl_verify": config_parser.get(
                "events-service-api", "ssl_verify", fallback=None
            ),
            "schema": config_parser.get(
                "events-service-api", "schema", fallback="db_stats"
            ),
        },
    }

    return config


def generate_controller_token():

    # logging.debug(f"url: {url}")
    # logging.debug(f"headers: {headers}")
    # logging.debug(f"d: {d}")
    logging.info(f"Get Controller Token")

    try:
        response = requests.post(
            f"{config["controller_api"]["url"]}/controller/api/oauth/access_token",
            data=f"grant_type=client_credentials&client_id={config["controller_api"]["client_id"]}&client_secret={config["controller_api"]["client_secret"]}",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=config["controller_api"]["ssl_verify"],
        )

        logging.info(f"Get Controller Token: Status [{response.status_code}]")

        if response.status_code != 200:
            logging.info(f"Get Controller Token: Error [{response.text}]")

        data = response.json()
        token = data["access_token"]
        logging.debug(f"Get Controller Token: Generated Token [{token[:20]}...]")
        return token
    except Exception as e:
        logging.error(f"Get Controller Token: Failed to authenticate [{type(e)}]")
        raise e


def get_db_stats(request):

    token = generate_controller_token()

    logging.info(f"Get DB Stats")
    response = requests.post(
        f"{config['controller_api']['url']}/controller/databasesui/databases/queryListData",
        json=request,
        headers={
            "Authorization": f"Bearer {token}",
        },
        verify=config["events_service_api"]["ssl_verify"],
    )
    logging.info(f"Get DB Stats: Status [{response.status_code}]")

    if response.status_code != 200:
        logging.info(f"Get DB Stats: Error [{response.text}]")
        return []

    return response.json()


def send_db_stats_to_analytics(analytics_data):

    logging.info(f"Send DB Stats")
    response = requests.post(
        f"{config["events_service_api"]["url"]}/events/publish/{config["events_service_api"]["schema"]}",
        json=analytics_data,
        headers={
            "Content-type": "application/vnd.appd.events+json;v=2",
            "X-Events-API-AccountName": config["events_service_api"]["account_name"],
            "X-Events-API-Key": config["events_service_api"]["api_key"],
        },
        verify=config["events_service_api"]["ssl_verify"],
    )

    logging.info(f"Send DB Stats: Status [{response.status_code}]")

    if response.status_code != 200:
        logging.info(f"Send DB Stats: Error [{response.text}]")


def generate_db_stats_body(start_timestamp, end_timestamp):
    request = {
        "dbConfigId": config["database_ui_api"]["db_config_id"],
        "dbServerId": config["database_ui_api"]["db_server_id"],
        "field": "query-id",
        "size": config["database_ui_api"]["db_config_size"],
        "filterBy": "time",
        "startTime": start_timestamp,
        "endTime": end_timestamp,
        "waitStateIds": [],
        "useTimeBasedCorrelation": False,
    }

    return request


def sync_db_stats_to_analytics():

    current_minute = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    start = current_minute - timedelta(minutes=1)
    start_timestamp = int(start.timestamp() * 1000)

    end = current_minute - timedelta(microseconds=1)
    end_timestamp = int(end.timestamp() * 1000)

    logging.info(
        f'Sync DB Stats: Start [{start.strftime("%Y-%m-%d %H:%M:%S.%f")}] / [{start_timestamp}]'
    )
    logging.info(
        f'Sync DB Stats: End   [{end.strftime("%Y-%m-%d %H:%M:%S.%f")}] / [{end_timestamp}]'
    )

    request = generate_db_stats_body(start_timestamp, end_timestamp)
    data = get_db_stats(request)

    while len(data) == 0:
        logging.info("Sync DB Stats: No data found. Wait for 30 sec...")
        time.sleep(30)
        logging.info("Sync DB Stats: Retrying...")
        data = get_db_stats(request)
    logging.debug(f"Sync DB Stats: Got DB Stats: {data}")

    analytics_data = generate_analytics_body(start_timestamp, data)
    logging.info("Sync DB Stats: Sending DB Stats to Analytics...")
    send_db_stats_to_analytics(analytics_data)
    logging.info("Sync DB Stats: DB Stats sent to Analytics")


def generate_analytics_body(start_timestamp, data):
    analytics_data = [
        {
            "eventTimestamp": start_timestamp,
            "queryHashCode": item["queryHashCode"],
            "queryText": item["queryText"],
            "hits": item["hits"],
            "weight": item["weight"],
        }
        for item in data
    ]

    return analytics_data


def worker_main():
    while 1:
        job_func = jobqueue.get()
        job_func()
        jobqueue.task_done()


config = load_config()

jobqueue = queue.Queue()
schedule.every().minute.at(":02").do(jobqueue.put, sync_db_stats_to_analytics)
logging.info("Scheduled Job")
worker_thread = threading.Thread(target=worker_main)
worker_thread.start()

while True:
    schedule.run_pending()
    time.sleep(1)
