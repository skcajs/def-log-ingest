import azure.functions as func
import logging
import json
import requests
import re
import os
from datetime import datetime, timezone

from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError

# Toggle mock mode
MOCK_MODE = os.environ.get("MOCK_MODE", "False").lower() in ["true", "1", "yes"]

# DCR/DCE settings
DCR_STREAM_NAME = os.environ.get("DCR_STREAM_NAME", "DEFAULT_STREAM")
DCR_IMMUTABLE_ID = os.environ.get("DCR_IMMUTABLE_ID", "DEFAULT_ID")
DCE_ENDPOINT = os.environ.get("DCE_ENDPOINT", "https://default-endpoint.com")

URL_ENDPOINT = os.environ.get("URL_ENDPOINT")

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="logs", methods=["GET"])
def log_ingestor(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Fetching logs from mock API...")

    # Fetch raw logs
    url = URL_ENDPOINT
    seconds = req.params.get("seconds")
    if seconds:
        url += f"?seconds={seconds}"
    r = requests.get(url, timeout=10)

    if r.status_code != 200:
        return func.HttpResponse(
            json.dumps({"error": "Failed to retrieve logs"}),
            mimetype="application/json",
            status_code=500
        )

    raw_logs = r.json()
    parsed_logs = [parse_cef(log) for log in raw_logs]

    if MOCK_MODE:
        return func.HttpResponse(
            json.dumps({
                "mock": True,
                "records_prepared": len(parsed_logs),
                "example_record": parsed_logs[0] if parsed_logs else None
            }, indent=2),
            mimetype="application/json",
            status_code=200
        )

    # Step 2: Authenticate with Managed Identity (DefaultAzureCredential)
    try:
        credential = DefaultAzureCredential()
        client = LogsIngestionClient(endpoint=DCE_ENDPOINT, credential=credential)
    except Exception as e:
        logging.error(f"Failed to create LogsIngestionClient: {e}")
        return func.HttpResponse("Auth error", status_code=500)

    # Step 3: Upload logs
    try:
        client.upload(rule_id=DCR_IMMUTABLE_ID, stream_name=DCR_STREAM_NAME, logs=parsed_logs)
        return func.HttpResponse("Logs ingested successfully", status_code=200)
    except HttpResponseError as e:
        logging.error(f"Ingestion failed: {e}")
        return func.HttpResponse(f"Ingestion failed: {e}", status_code=500)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return func.HttpResponse("Unexpected error during ingestion", status_code=500)

# Helper function to parse CEF
def parse_cef(cef_line: str) -> dict:
    """
    Parse a CEF (Common Event Format) log line.
    Args:
        cef_line (str): The CEF log line to parse.
    Returns:
        dict: Parsed CEF fields as a dictionary.
        If the CEF line is invalid, returns a dictionary with an "error" key.
    """
    
    header_parts = cef_line.split('|', 7)
    if len(header_parts) < 8:
        return {"error": "Invalid CEF format"}

    cef_prefix = header_parts[0]
    device_vendor = header_parts[1]
    device_product = header_parts[2]
    device_version = header_parts[3]
    signature_id = header_parts[4]
    name = header_parts[5]
    severity = header_parts[6]
    extension = header_parts[7]

    extension_fields = dict(re.findall(r'(\w+)=([^\s]+)', extension))

    if 'rt' in extension_fields:
        try:
            rt_int = int(extension_fields['rt'])
            extension_fields['rt'] = datetime.fromtimestamp(rt_int, tz=timezone.utc).isoformat()
        except ValueError:
            extension_fields['rt'] = extension_fields['rt']

    return {
        "cef_version": cef_prefix.split(':')[1],
        "device_vendor": device_vendor,
        "device_product": device_product,
        "device_version": device_version,
        "signature_id": signature_id,
        "name": name,
        "severity": int(severity),
        **extension_fields
    }