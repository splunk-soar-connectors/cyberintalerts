# Cyberint Alerts

Publisher: Check Point Cyberint <br>
Connector Version: 1.0.2 <br>
Product Vendor: Check Point Cyberint <br>
Product Name: Cyberint Alerts <br>
Minimum Product Version: 6.4.0

Cyberint and Splunk SOAR integration is here to simplify and streamline alerts for Splunk SOAR, bring enriched threat intelligence from the Argos Edge™ Digital Risk Protection Platform into Splunk SOAR and automatically implement playbooks and incident processes.

### Configuration variables

This table lists the configuration variables required to operate Cyberint Alerts. These variables are specified when configuring a Cyberint Alerts asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | Base URL of the Cyberint API |
**access_token** | required | password | API Access Token for authentication |
**customer_name** | required | string | The name of the company |

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration <br>
[get enriched alerts](#action-get-enriched-alerts) - Get alerts and enrich them with indicator details <br>
[alerts - update alert status](#action-alerts---update-alert-status) - Update the status of one or more alerts <br>
[alerts - submit takedown](#action-alerts---submit-takedown) - Submit a takedown request <br>
[alerts - retrieve takedowns](#action-alerts---retrieve-takedowns) - Retrieve takedown requests <br>
[on poll](#action-on-poll) - Ingest Cyberint alerts and create cases

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get enriched alerts'

Get alerts and enrich them with indicator details

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Alert_Types** | optional | Comma-separated list of alert types to fetch (leave empty for all types) | string | |
**Severities** | optional | Comma-separated severity levels to filter (leave empty for all severities) | string | |
**Statuses** | optional | Comma-separated statuses to filter (leave empty for all statuses) | string | |
**Include_CSV_Attachments** | optional | Include CSV attachments as JSON content in the response | boolean | |
**Page_Size** | optional | Number of alerts to fetch per page (10-100, default: 50) | numeric | |

**Available Alert Types:** refund_fraud, carding, coupon_fraud, money_laundering, victim_report, malicious_insider, extortion, phishing_email, phishing_kit, phishing_website, lookalike_domain, phishing_target_list, malicious_file, reconnaissance, automated_attack_tools, business_logic_bypass, target_list, official_social_media_profile, impersonation, intellectual_property_infringement, unauthorized_trading, negative_sentiment, fake_job_posting, defacement, compromised_pii, internal_information_disclosure, compromised_payment_cards, compromised_employee_credentials, compromised_customer_credentials, compromised_access_token, ransomware, exposed_web_interfaces, hijackable_subdomains, website_vulnerabilities, vulnerabilities, exposed_cloud_storage, exploitable_ports, mail_servers_in_blacklist, server_connected_to_botnet, email_security_issues, certificate_authority_issues, user_defined_saved_query, other, ssl_tls, web_app_security

**Available Severities:** low, medium, high, very_high

**Available Statuses:** open, acknowledged, closed

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.Alert_Types | string | | |
action_result.parameter.Severities | string | | |
action_result.parameter.Statuses | string | | |
action_result.parameter.Include_CSV_Attachments | boolean | | |
action_result.parameter.Page_Size | numeric | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.status | string | | |

## action: 'alerts - update alert status'

Update the status of one or more alerts

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Alert_Ref_IDs** | required | Comma-separated list of alert reference IDs to update | string | |
**Status** | required | The new status for the alerts | string | |
**Closure_Reason** | optional | The reason for closing the alert | string | |
**Reason_Description** | optional | A description for the closure reason | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.Alert_Ref_IDs | string | | |
action_result.parameter.Status | string | | |
action_result.parameter.Closure_Reason | string | | |
action_result.parameter.Reason_Description | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.status | string | | |

## action: 'alerts - submit takedown'

Submit a takedown request

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Customer_ID** | required | Your Cyberint Customer ID | string | |
**Reason** | required | Reason for the takedown | string | |
**URL** | required | URL to take down | string | |
**Brand** | required | The brand being impersonated | string | |
**Original_URL** | optional | The original/legitimate URL | string | |
**Alert_ID** | optional | The ID of the related alert | numeric | |
**Note** | optional | Additional notes for the takedown request | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.Customer_ID | string | | |
action_result.parameter.Reason | string | | |
action_result.parameter.URL | string | | |
action_result.parameter.Brand | string | | |
action_result.parameter.Original_URL | string | | |
action_result.parameter.Alert_ID | numeric | | |
action_result.parameter.Note | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.status | string | | |

## action: 'alerts - retrieve takedowns'

Retrieve takedown requests

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Customer_ID** | required | Your Cyberint Customer ID | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.Customer_ID | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |
action_result.status | string | | |

## action: 'on poll'

Ingest Cyberint alerts and create cases

Type: **ingest** <br>
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
