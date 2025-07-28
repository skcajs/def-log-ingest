# Defendable Log Ingestor - Azure Function

This Azure Function ingests simulated firewall and security logs from a public mock API into a Microsoft Sentinel-enabled Log Analytics workspace via the **Logs Ingestion API**. Logs are parsed from CEF format into structured JSON.

## Architecutre


| Step | Component                    | Description |
|------|------------------------------|-------------|
| 1    | **Function Endpoint**        | HTTP-triggered Azure Function App |
| 2    | **Mock API**                 | External mock source for CEF logs |
| 3    | **Log Parser**               | Parses raw CEF strings into structured fields |
| 4    | **Data Collection Endpoint**                      | Sends structured logs securely to Azure Monitor |
| 5    | **Data Collection Rule**     | Routes and transforms log data |
| 6    | **Log Analytics / Sentinel** | Final destination for querying and detection |


## Features

- HTTP-triggered Function (`/api/logs?seconds=N`)
- Pulls real-time logs from a mock endpoint
- Parses CEF logs into structured JSON
- Sends logs to Azure Monitor Logs Ingestion API
- Mock mode for development/testing without authentication
- Supports secure authentication using Azure App Registration

## Endpoint
GET /api/logs?seconds=60

| Param   | Description                     |
|---------|---------------------------------|
| seconds | Number of seconds to fetch logs for |


## Configuration

Set the following **App Settings** in your Azure Function (Portal → Configuration):

| Key                    | Description                          |
|------------------------|--------------------------------------|
| `AZURE_TENANT_ID`      | Your Azure AD Tenant ID              |
| `AZURE_CLIENT_ID`      | App Registration Client ID           |
| `AZURE_CLIENT_SECRET`  | App Registration Client Secret       |

Set the following constants in `local.settings.json`:

```python
MOCK_MODE = True  # Set to False when real auth is configured

DCR_STREAM_NAME = "Custom-FirewallLogs_CL"
DCR_IMMUTABLE_ID = "<your-dcr-immutable-id>"
DCE_ENDPOINT = "https://<your-dce-name>.<region>.ingest.monitor.azure.com"
```

## Tests

To run the tests, use:

```
PYTHONPATH=. pytest
```

## Azure

### Resources

| Resource Name                | Type                    | Region       | Resource Group              | Subscription                |
|-----------------------------|-------------------------|--------------|-----------------------------|-----------------------------|
| `defendable-function-app`   | Function App            | Norway East  | `rg-lab-candidate-dev-001`  | `subdefendablelab001lab`    |
| `dcr-firewalllogs`          | Data Collection Rule    | Norway East  | `rg-lab-candidate-dev-001`  | `subdefendablelab001lab`    |
| `dce-firewalllogs`          | Data Collection Endpoint| Norway East  | `rg-lab-candidate-dev-001`  | `subdefendablelab001lab`    |
| `log-lab-candidate-dev-001` | Log Analytics Workspace | Norway East  | `rg-lab-candidate-dev-001`  | `subdefendablelab001lab`    |
| `rg-lab-candidate-dev-001`  | Resource Group          | Norway East  | N/A                         | `subdefendablelab001lab`    |

### Indentities and Roles

dcr-firewalllogs: Role, Monitoring Metrics Publisher

defendable-function-app: Identity, system-assigned 


## TODO

A list of key improvements and enhancements to take the solution from functional to production-ready:

- **Define Bicep Templates**  
  Create reusable Bicep templates for deploying the Function App, DCR, DCE, Log Analytics, and supporting resources.

- **Add Retry Logic & Scheduled Trigger**  
  Implement retry logic for the HTTP request to the mock API, and optionally add a CRON-based timer trigger to fetch logs on a schedule.

- **Add Ingestion Chunking & Limits**  
  Respect Azure Monitor API limits (500 records or ~1MB per request) and add batching logic. Optionally set a max record count per request.

- **Introduce Environment Separation (Dev/Prod)**  
  Use deployment slots or separate environments with appropriate environment variables and configurations (DCR/DCE/workspace separation).

- **Integrate Application Insights**  
  Enable and configure Application Insights for end-to-end observability (function invocations, failures, durations).

- **Store Failed Log Batches in Blob Storage**  
  Implement fallback logic to write failed ingestion attempts to Azure Blob Storage for recovery and auditing.