# File: firesight_consts.py
#
# Copyright (c) 2015-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
FIRESIGHT_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
FIRESIGHT_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
FIRESIGHT_ERR_CONNECT = "Failed to connect to device"
FIRESIGHT_ERR_NO_PARAMS_PRESENT = "None of the parameters specified, please specify one of {param_names}."
FIRESIGHT_SUCC_NO_MATCH = "Query executed successfully, but signature not found"
FIRESIGHT_ERR_EXECUTING_QUERY = "Error executing query"
FIRESIGHT_ERR_FETCHING_RESULTS = "Error fetching results"

FIRESIGHT_JSON_DEVICE = "device"
FIRESIGHT_JSON_PORT = "port"
FIRESIGHT_JSON_USERNAME = "username"
FIRESIGHT_JSON_PASSWORD = "password"
FIRESIGHT_JSON_SNORT_ID = "snort_id"
FIRESIGHT_JSON_BUGTRAQ_ID = "bugtraq_id"
FIRESIGHT_JSON_SVID = "svid"
FIRESIGHT_JSON_TOTAL_SIGS = "total_signatures"

FIRESIGHT_JDBC_DB_URL = "jdbc:vjdbc:rmi://{device}:{port}/VJdbc,eqe"
FIRESIGHT_JDBC_DRIVER_CLASS = "com.sourcefire.vjdbc.VirtualDriver"
FIRESIGHT_JDBC_DRIVER_JAR_FILES = ["commons-logging-1.1.jar", "vjdbc.jar"]
FIRESIGHT_DEFAULT_PORT = 2000
# The columns that will be queried for, keep it a list, easy to match the results to this column to create a result dictionary
FIRESIGHT_SIG_INFO_COLUMNS = ["available_exploits", "bugtraq_id", "exploit", "remote", "rna_vuln_id", "short_description", "snort_id", "title"]
FIRESIGHT_MSG_TIMEOUT_TRY_AGAIN = "Got timeout error, trying again"
