# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

import re


CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def normalize_cve_id(value):
    if not isinstance(value, str) or CVE_ID_PATTERN.fullmatch(value) is None:
        return None
    return value.upper()
