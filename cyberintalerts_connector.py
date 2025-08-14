#!/usr/bin/python
# -----------------------------------------
# Phantom App Connector python file
# -----------------------------------------

import json

import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from cyberintalerts_consts import (
    ALERTS_ENDPOINT,
    ALERTS_STATUS_ENDPOINT,
    TAKEDOWN_REQUEST_ENDPOINT,
    TAKEDOWN_SUBMIT_ENDPOINT,
    ClosureReason,
    Status,
    TakedownReason,
)


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


def map_severity(severity_str):
    """Maps Cyberint severity to Splunk SOAR severity."""
    if not severity_str:
        return "low"
    sev_lower = severity_str.lower()
    if sev_lower == "very_high":
        return "high"
    if sev_lower in ["high", "medium", "low"]:
        return sev_lower
    return "low"


class CyberintAlertsConnector(BaseConnector):
    def __init__(self):
        super().__init__()
        self._state = None
        self._base_url = None
        self._access_token = None
        self._customer_id = None
        self._customer_name = None

    def _get_custom_headers(self):
        app_json = self.get_app_json()
        config = self.get_config()
        return {
            "X-Integration-Type": "Splunk SOAR",
            "X-Integration-Instance-Name": config.get("asset_name"),
            "X-Integration-Instance-Id": str(self.get_asset_id()),
            "X-Integration-Customer-Name": self._customer_name,
            "X-Integration-Version": app_json.get("app_version"),
        }

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()
        self._base_url = config.get("base_url")
        self._access_token = config.get("access_token")
        self._customer_name = config.get("customer_name")
        return phantom.APP_SUCCESS

    def _process_response(self, r, action_result):
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        if "json" in r.headers.get("Content-Type", ""):
            try:
                resp_json = r.json()
            except Exception as e:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, f"Unable to parse JSON response. Error: {e}"),
                    None,
                )
            if 200 <= r.status_code < 399:
                return RetVal(phantom.APP_SUCCESS, resp_json)
            message = f"Error from server. Status Code: {r.status_code} Data from server: {r.text}"
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        if "html" in r.headers.get("Content-Type", ""):
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                error_text = "\n".join([x.strip() for x in soup.text.split("\n") if x.strip()])
            except:
                error_text = "Cannot parse error details"
            message = f"Status Code: {r.status_code}. Data from server:\n{error_text}\n"
            return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

        if not r.text:
            if r.status_code == 200:
                return RetVal(phantom.APP_SUCCESS, {})
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                None,
            )

        message = f"Can't process response from server. Status Code: {r.status_code} Data from server: {r.text}"
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        config = self.get_config()
        cookies = {"access_token": self._access_token}
        kwargs["cookies"] = cookies

        headers = self._get_custom_headers()
        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        kwargs["headers"] = headers

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"),
                None,
            )

        url = self._base_url + endpoint
        try:
            r = request_func(url, verify=config.get("verify_server_cert", False), **kwargs)
        except Exception as e:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Error Connecting to server. Details: {e}"),
                None,
            )

        return self._process_response(r, action_result)

    def _get_full_alert_from_ref_id(self, ref_ids: list[str], action_result):
        full_alerts = []
        for ref_id in ref_ids:
            ret_val, response = self._make_rest_call(f"{ALERTS_ENDPOINT}/{ref_id}", action_result)
            if phantom.is_fail(ret_val):
                return ret_val, None
            full_alerts.append(response["alert"])
        return phantom.APP_SUCCESS, full_alerts

    def _enrich_alert_indicators(self, alerts: list[dict], action_result):
        for alert in alerts:
            ref_id = alert.get("ref_id")
            for idx, indicator in enumerate(alert["indicators"]):
                ret_val, response = self._make_rest_call(
                    f"{ALERTS_ENDPOINT}/{ref_id}/indicators/{indicator['id']}",
                    action_result,
                )
                if phantom.is_fail(ret_val):
                    return ret_val, None
                alert["indicators"][idx] = response
        return phantom.APP_SUCCESS, alerts

    def _handle_get_enriched_alerts(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print(f"Fetching alerts from {ALERTS_ENDPOINT}")
        ret_val, response = self._make_rest_call(ALERTS_ENDPOINT, action_result, method="post", json={})
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.debug_print(f"Initial API response: {response}")

        alerts = response.get("alerts", [])
        self.debug_print(f"Found {len(alerts)} alerts in initial response.")

        ref_ids = [alert["ref_id"] for alert in alerts]
        self.debug_print(f"Enriching ref_ids: {ref_ids}")

        ret_val, full_alerts = self._get_full_alert_from_ref_id(ref_ids, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, enriched_alerts = self._enrich_alert_indicators(full_alerts, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        for alert in enriched_alerts:
            action_result.add_data(alert)
        action_result.update_summary({"alerts_enriched": len(enriched_alerts)})
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_alert_status(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        alert_ref_ids = [x.strip() for x in param["Alert_Ref_IDs"].split(",")]

        status = param["Status"]
        if status not in [member.value for member in Status]:
            return action_result.set_status(phantom.APP_ERROR, f"Invalid status value: {status}")

        closure_reason = param.get("Closure_Reason")
        if closure_reason and closure_reason not in [member.value for member in ClosureReason]:
            return action_result.set_status(phantom.APP_ERROR, f"Invalid closure_reason value: {closure_reason}")

        body = {
            "alert_ref_ids": alert_ref_ids,
            "data": {
                "status": status,
                "closure_reason": closure_reason,
                "closure_reason_description": param.get("Reason_Description"),
            },
        }
        ret_val, response = self._make_rest_call(ALERTS_STATUS_ENDPOINT, action_result, method="put", json=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_submit_takedown(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        reason = param["Reason"]
        if reason not in [member.value for member in TakedownReason]:
            return action_result.set_status(phantom.APP_ERROR, f"Invalid takedown reason value: {reason}")

        takedown = {
            "customer": param["Customer_ID"],
            "reason": reason,
            "url": param["URL"],
            "brand": param["Brand"],
            "original_url": param.get("Original_URL"),
            "alert_id": param.get("Alert_ID"),
            "note": param.get("Note"),
        }
        ret_val, response = self._make_rest_call(TAKEDOWN_SUBMIT_ENDPOINT, action_result, method="post", json=takedown)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        action_result.add_data(response)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_retrieve_takedowns(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        customer_id = param.get("Customer_ID")
        if not customer_id:
            return action_result.set_status(phantom.APP_ERROR, "Customer_ID is a required parameter.")

        body = {"customer_id": customer_id, "filters": {}}
        ret_val, response = self._make_rest_call(TAKEDOWN_REQUEST_ENDPOINT, action_result, method="post", json=body)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        for takedown in response.get("requests", []):
            action_result.add_data(takedown)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_test_connectivity(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint...")
        ret_val, response = self._make_rest_call(ALERTS_ENDPOINT, action_result, method="post", json={})
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()
        self.save_progress("Test Connectivity Passed.")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ingest_alerts(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Starting alert ingestion...")

        self.debug_print("Fetching raw alerts...")
        ret_val, response = self._make_rest_call(ALERTS_ENDPOINT, action_result, method="post", json={})
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        alerts = response.get("alerts", [])
        self.save_progress(f"Found {len(alerts)} alerts to process.")
        if not alerts:
            return action_result.set_status(phantom.APP_SUCCESS, "No new alerts found.")

        ref_ids = [alert["ref_id"] for alert in alerts]
        self.debug_print(f"Enriching {len(ref_ids)} alerts: {ref_ids}")

        ret_val, enriched_alerts = self._get_full_alert_from_ref_id(ref_ids, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, enriched_alerts = self._enrich_alert_indicators(enriched_alerts, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress("Enrichment complete. Saving to Splunk SOAR...")
        for alert in enriched_alerts:
            self.save_progress(f"Full Alert Object: {json.dumps(alert, indent=2)}")
            self.save_progress(f"Processing alert {alert.get('ref_id')}")

            # 1. Direct Mapping for Key Fields
            container = {
                "name": alert.get("title", "Cyberint Alert"),
                "description": alert.get("description", ""),
                "source_data_identifier": alert.get("ref_id"),
                "severity": map_severity(alert.get("severity")),
                "tags": alert.get("tags", []),
            }
            status, message, container_id = self.save_container(container)
            if phantom.is_fail(status):
                self.debug_print(f"Failed to save container for alert {alert.get('ref_id')}: {message}")
                continue

            self.debug_print(f"Successfully created container {container_id} for alert {alert.get('ref_id')}")

            # 2. "Catch-All" Artifact for remaining details
            alert_details = alert.copy()
            alert_details.pop("title", None)
            alert_details.pop("description", None)
            alert_details.pop("severity", None)
            alert_details.pop("tags", None)
            alert_details.pop("ref_id", None)
            alert_details.pop("indicators", None)  # We handle these separately below

            details_artifact = {
                "name": "Alert Details",
                "container_id": container_id,
                "source_data_identifier": f"{alert.get('ref_id')}_details",
                "cef": alert_details,
            }
            self.save_artifact(details_artifact)

            # 3. Process and save indicators
            for indicator in alert.get("indicators", []):
                self.save_progress(f"Full Indicator Object: {json.dumps(indicator, indent=2)}")
                self.debug_print(f"Adding indicator {indicator.get('value')} to container {container_id}")
                artifact = {
                    "name": indicator.get("value"),
                    "cef": {
                        "type": indicator.get("type"),
                        "value": indicator.get("value"),
                        "confidence": indicator.get("confidence"),
                        "source_category": indicator.get("source_category"),
                    },
                    "container_id": container_id,
                    "source_data_identifier": indicator.get("id"),
                }
                self.save_artifact(artifact)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        if hasattr(self, "_get_requests_session"):
            self._requests_session = self._get_requests_session()
        ret_val = phantom.APP_SUCCESS
        action_id = self.get_action_identifier()
        self.debug_print("action_id", action_id)

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)
        elif action_id == "get_enriched_alerts":
            ret_val = self._handle_get_enriched_alerts(param)
        elif action_id == "update_alert_status":
            ret_val = self._handle_update_alert_status(param)
        elif action_id == "submit_takedown":
            ret_val = self._handle_submit_takedown(param)
        elif action_id == "retrieve_takedowns":
            ret_val = self._handle_retrieve_takedowns(param)
        elif action_id == "on_poll":
            ret_val = self._handle_ingest_alerts(param)

        return ret_val

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("input_test_json", help="Input Test JSON file")
    args = parser.parse_args()

    with open(args.input_test_json) as f:
        in_json = json.load(f)

    connector = CyberintAlertsConnector()
    connector.print_progress_message = True

    # Mock the config for local testing
    connector._base_url = in_json["config"].get("base_url")
    connector._access_token = in_json["config"].get("access_token")
    connector._customer_id = in_json["config"].get("customer_id")

    # Mock get_action_identifier
    connector._action_identifier = in_json.get("action")

    ret_val = connector.handle_action(in_json.get("parameters", [{}])[0])
    print(ret_val)

    sys.exit(0)
