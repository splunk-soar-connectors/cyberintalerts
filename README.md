# Cyberint Alerts

Welcome to the open-source repository for Splunk SOAR's Cyberint Alerts App.

## Contributing

Please have a look at our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) for guidelines if you are interested in contributing, raising issues, or learning more about open-source SOAR apps.

Please also review our [Conventions](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md) to ensure you follow up-to-date standards.

## Legal and License

This SOAR App is licensed under the Apache 2.0 license. Please see our [Contributing Guide](https://github.com/Splunk-SOAR-Apps/.github/blob/main/.github/CONTRIBUTING.md#legal-notice) for further details.

# Cyberint Alerts

Publisher: Check Point Cyberint \
Connector Version: 1.0.0 \
Product Vendor: Check Point Cyberint \
Product Name: Cyberint Alerts \
Minimum Product Version: 6.4.0

Cyberint and Splunk SOAR integration is here to simplify and streamline alerts for Splunk SOAR, bring enriched threat intelligence from the Argos Edge™ Digital Risk Protection Platform into Splunk SOAR and automatically implement playbooks and incident processes.

### Configuration variables

This table lists the configuration variables required to operate Cyberint Alerts. These variables are specified when configuring a Cyberint Alerts asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** | required | string | Base URL of the Cyberint API
**access_token** | required | password | API Access Token for authentication
**customer_name** | required | string | The name of the company

### Supported Actions

[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration \
[get enriched alerts](#action-get-enriched-alerts) - Get alerts and enrich them with indicator details \
[alerts - update alert status](#action-alerts---update-alert-status) - Update the status of one or more alerts \
[alerts - submit takedown](#action-alerts---submit-takedown) - Submit a takedown request \
[alerts - retrieve takedowns](#action-alerts---retrieve-takedowns) - Retrieve takedown requests \
[on poll](#action-on-poll) - Ingest Cyberint alerts and create cases

## action: 'test connectivity'

Validate the asset configuration for connectivity using supplied configuration

Type: **test** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

## action: 'get enriched alerts'

Get alerts and enrich them with indicator details

Type: **investigate** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.message | string | |
summary.total_objects | numeric | |
summary.total_objects_successful | numeric | |
action_result.status | string | | success failed

## action: 'alerts - update alert status'

Update the status of one or more alerts

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Alert_Ref_IDs** | required | Comma-separated list of alert reference IDs to update | string |
**Status** | required | The new status for the alerts | string |
**Closure_Reason** | optional | The reason for closing the alert | string |
**Reason_Description** | optional | A description for the closure reason | string |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.Alert_Ref_IDs | string | |
action_result.parameter.Status | string | |
action_result.parameter.Closure_Reason | string | |
action_result.parameter.Reason_Description | string | |
action_result.message | string | |
summary.total_objects | numeric | |
summary.total_objects_successful | numeric | |
action_result.status | string | | success failed

## action: 'alerts - submit takedown'

Submit a takedown request

Type: **generic** \
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Customer_ID** | required | Your Cyberint Customer ID | string |
**Reason** | required | Reason for the takedown | string |
**URL** | required | URL to take down | string |
**Brand** | required | The brand being impersonated | string |
**Original_URL** | optional | The original/legitimate URL | string |
**Alert_ID** | optional | The ID of the related alert | numeric |
**Note** | optional | Additional notes for the takedown request | string |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.Customer_ID | string | |
action_result.parameter.Reason | string | |
action_result.parameter.URL | string | |
action_result.parameter.Brand | string | |
action_result.parameter.Original_URL | string | |
action_result.parameter.Alert_ID | numeric | |
action_result.parameter.Note | string | |
action_result.message | string | |
summary.total_objects | numeric | |
summary.total_objects_successful | numeric | |
action_result.status | string | | success failed

## action: 'alerts - retrieve takedowns'

Retrieve takedown requests

Type: **investigate** \
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**Customer_ID** | required | Your Cyberint Customer ID | string |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.Customer_ID | string | |
action_result.message | string | |
summary.total_objects | numeric | |
summary.total_objects_successful | numeric | |
action_result.status | string | | success failed

## action: 'on poll'

Ingest Cyberint alerts and create cases

Type: **ingest** \
Read only: **True**

#### Action Parameters

No parameters are required for this action

#### Action Output

No Output

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Check Point Cyberint.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
