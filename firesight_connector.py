# --
# File: firesight_connector.py
#
# Copyright (c) 2015-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
# --

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from firesight_consts import *

# Other imports
import jaydebeapi
import os


class FiresightConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_GET_SIGINFO = "get_signature_info"

    def __init__(self):

        # Call the BaseConnectors init first
        super(FiresightConnector, self).__init__()

        self.__conn = None
        self._timeout_on_execute = False

    def initialize(self):

        app_dir = os.path.dirname(os.path.realpath(__file__))

        # install the certificate
        config = self.get_config()
        device = config[FIRESIGHT_JSON_DEVICE]

        phantom.run_ext_command("java -Djava.class.path={0} InstallCert {1}".format(app_dir, device))

        # Get the directory of the python file
        # Create the CLASSPATH variable value
        classpath = ':'.join([os.path.join(app_dir.strip(), 'lib', x.strip()) for x in FIRESIGHT_JDBC_DRIVER_JAR_FILES])
        os.environ['CLASSPATH'] = classpath

        self.debug_print("Set Classpath as:", classpath)

        return phantom.APP_SUCCESS

    def _connect(self):

        self.debug_print("GOT Classpath as:", os.getenv('CLASSPATH'))

        config = self.get_config()

        device = config[FIRESIGHT_JSON_DEVICE]
        port = config.get(FIRESIGHT_JSON_PORT, FIRESIGHT_DEFAULT_PORT)

        username = config[phantom.APP_JSON_USERNAME]
        password = config[phantom.APP_JSON_PASSWORD]

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, device)

        try:
            self.__conn = jaydebeapi.connect(FIRESIGHT_JDBC_DRIVER_CLASS, FIRESIGHT_JDBC_DB_URL.format(device=device, port=port), [username, password])
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, FIRESIGHT_ERR_CONNECT, e)

        if self.__conn is None:
            return self.set_status(phantom.APP_ERROR, FIRESIGHT_ERR_CONNECT)

        return phantom.APP_SUCCESS

    def _get_siginfo(self, param, action_result):

        snort_id = param.get(FIRESIGHT_JSON_SNORT_ID)
        bugtraq_id = param.get(FIRESIGHT_JSON_BUGTRAQ_ID)
        svid = param.get(FIRESIGHT_JSON_SVID)

        query = None
        select_clause = "select {0} from rna_vuln".format(','.join(FIRESIGHT_SIG_INFO_COLUMNS))

        if snort_id is not None:
            query = "{0} where snort_id={1}".format(select_clause, snort_id)
        elif bugtraq_id is not None:
            query = "{0} where bugtraq_id={1}".format(select_clause, bugtraq_id)
        elif svid is not None:
            query = "{0} where rna_vuln_id={1}".format(select_clause, svid)
        else:
            param_names = "{0}, {1} or {2}".format(FIRESIGHT_JSON_SNORT_ID, FIRESIGHT_JSON_BUGTRAQ_ID, FIRESIGHT_JSON_SVID)
            return action_result.set_status(phantom.APP_ERROR, FIRESIGHT_ERR_NO_PARAMS_PRESENT, param_names=param_names)

        if phantom.is_fail(self._connect()):
            self.debug_print("connect failed")
            return self.get_status()

        curs = self.__conn.cursor()

        try:
            curs.execute(query)
        except Exception as e:
            if (str(e).find('wait_timeout') != -1):
                self._timeout_on_execute = True
            return action_result.set_status(phantom.APP_ERROR, FIRESIGHT_ERR_EXECUTING_QUERY)

        try:
            results = curs.fetchall()
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, FIRESIGHT_ERR_FETCHING_RESULTS)

        if results:
            action_result.update_summary({FIRESIGHT_JSON_TOTAL_SIGS: len(results)})

        if len(results) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, FIRESIGHT_SUCC_NO_MATCH)

        for result in results:
            result_dict = {x: y for x, y in zip(FIRESIGHT_SIG_INFO_COLUMNS, result)}
            action_result.add_data(result_dict)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_asset_connectivity(self, param):

        if phantom.is_fail(self._connect()):
            self.debug_print("connect failed")
            self.save_progress(FIRESIGHT_ERR_CONNECTIVITY_TEST)
            return self.append_to_message(FIRESIGHT_ERR_CONNECTIVITY_TEST)

        self.debug_print("connect passed")
        return self.set_status_save_progress(phantom.APP_SUCCESS, FIRESIGHT_SUCC_CONNECTIVITY_TEST)

    def handle_action(self, param):
        """"""
        action = self.get_action_identifier()

        # Process it
        if action == self.ACTION_ID_GET_SIGINFO:
            # Create an action_result here, we might end up calling the siginfo function twice
            action_result = self.add_action_result(ActionResult(dict(param)))

            ret_val = self._get_siginfo(param, action_result)
            if phantom.is_fail(ret_val) and self._timeout_on_execute is True:
                # Try once more
                self.save_progress(FIRESIGHT_MSG_TIMEOUT_TRY_AGAIN)
                ret_val = self._get_siginfo(param, action_result)
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            self._test_asset_connectivity(param)

        return self.get_status()


if __name__ == '__main__':

    import sys
    try:
        import simplejson as json
    except:
        pass

    import pudb

    pudb.set_trace()

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=' ' * 4))

        connector = FiresightConnector()
        connector._handle_action(json.dumps(in_json), None)

    exit(0)
