""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from time import time
from datetime import datetime, timedelta
from .constants import *
from connectors.core.utils import update_connnector_config
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('fortinet-forticasb')


class FortiCASB:
    def __init__(self, config):
        self.server_url = config.get('server_url').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url
        self.secret = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def convert_ts_epoch(self, ts):
        datetime_object = datetime.fromtimestamp(ts/1000)
        return datetime_object.timestamp()

    def generate_token(self):
        try:
            data = {
                "grant_type": "client_credentials"
            }

            resp = self.make_api_call(
                endpoint="auth/credentials/token/", method="POST", data=data, is_token_call=True)
            return resp
        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))

    def validate_token(self, connector_config):
        ts_now = time()
        # generate new token
        if not connector_config.get('token'):
            logger.info("Token does not exist")
            token_resp = self.generate_token()
            connector_config['token'] = token_resp['access_token']
            connector_config['expiresAt'] = token_resp['expires']
            connector_info = connector_config.get('connector_info')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                     connector_config,
                                     connector_config['config_id'])
            return "Bearer {0}".format(connector_config.get('token'))
        # check token expiry
        else:
            expires = connector_config['expiresAt']
            expires_ts = self.convert_ts_epoch(expires)
            if ts_now > float(expires_ts):
                logger.info("Token expired at {0}".format(expires))
                token_resp = self.generate_token()
                connector_config['token'] = token_resp['access_token']
                connector_config['expiresAt'] = token_resp['expires']
                connector_info = connector_config.get('connector_info')
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                         connector_config,
                                         connector_config['config_id'])

                return "Bearer {0}".format(connector_config.get('token'))
            else:
                logger.info("Token is valid till {0}".format(expires))
                return "Bearer {0}".format(connector_config.get('token'))

    def make_api_call(self, config=None, endpoint=None, params=None, method='GET', data=None,  additional_headers=None, is_token_call=False, is_next_page=False):
        if is_next_page:
            url = endpoint
        else:
            url = '{0}{1}{2}'.format(self.server_url, '/api/v1/', endpoint)
        logger.info('Request URL {0}'.format(url))

        # try:
        if is_token_call:
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {self.secret}"
            }
            response = requests.request(method=method, url=url,
                                        params=params, headers=headers, data=data, verify=self.verify_ssl)
        else:
            token = self.validate_token(config)
            headers = {
                "Content-Type": "application/json",
                'Authorization': token
            }
            if additional_headers:
                headers = headers | additional_headers

            response = requests.request(method=method, url=url,
                                        params=params, headers=headers, json=data, verify=self.verify_ssl)

        if response.status_code in [200, 201]:
            if response.text != "":
                return response.json()
        elif response.status_code == 204:
            return {"status": 'ok', "message": 'No content'}
        else:
            if response.text != "":
                err_resp = response.json()
                failure_msg = err_resp['message']
                error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                     failure_msg if failure_msg else '')
            else:
                error_msg = 'Response [{0}:{1}]'.format(
                    response.status_code, response.reason)
            logger.error(error_msg)
            raise ConnectorError(error_msg)
        # except requests.exceptions.SSLError:
        #     logger.error('An SSL error occurred')
        #     raise ConnectorError('An SSL error occurred')
        # except requests.exceptions.ConnectionError:
        #     logger.error('A connection error occurred')
        #     raise ConnectorError('A connection error occurred')
        # except requests.exceptions.Timeout:
        #     logger.error('The request timed out')
        #     raise ConnectorError('The request timed out')
        # except requests.exceptions.RequestException:
        #     logger.error('There was an error while handling the request')
        #     raise ConnectorError(
        #         'There was an error while handling the request')
        # except Exception as err:
        #     raise ConnectorError(str(err))


def build_params(params):
    return {k: v for k, v in params.items() if v is not None and v != ''}


def str_to_list(param):
    if ',' in param:
        return [item.strip() for item in param.split(',')]
    return [param.strip()]


def search_alerts(config, params):
    payload = {}
    params = build_params(params)
    if params:
        payload = payload | params
    if params.get('startTime'):
        # 2024-12-14T08:00:00.000Z
        payload['startTime'] = str(
            round(datetime.strptime(params.get('startTime'), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()) * 1000)
    else:
        now = datetime.utcnow()
        start_time = (now - timedelta(days=7)
                      ).strftime(f"%s%f")[:-3]
        payload['startTime'] = int(start_time)
    if params.get('endTime'):
        payload['endTime'] = str(
            round(datetime.strptime(params.get('endTime'), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()) * 1000)
    else:
        now = datetime.utcnow()
        end_time = now.strftime(f"%s%f")[:-3]
        payload['endTime'] = int(end_time)
    if params.get('skip'):
        payload['skip'] = int(params.get('skip'))
    else:
        payload['skip'] = 0
    if params.get('limit'):
        payload['limit'] = int(params.get('limit'))
    else:
        payload['limit'] = 100

    if not params.get('user'):
        payload["user"] = []
    else:
        payload["user"] = [s.strip() for s in params.get('user').split(",")]

    if not params.get('policy'):
        payload["policy"] = []
    else:
        payload["policy"] = [s.strip()
                             for s in params.get('policy').split(",")]

    if not params.get('activity'):
        payload["activity"] = []
    else:
        payload["activity"] = [s.strip()
                               for s in params.get('activity').split(",")]

    if not params.get('objectIdList'):
        payload["objectIdList"] = []
    else:
        payload["objectIdList"] = [s.strip()
                                   for s in params.get('objectIdList').split(",")]

    if not params.get('objectName'):
        payload["objectName"] = ""
    else:
        payload["objectName"] = params.get('objectName')

    if not params.get('severity'):
        payload["severity"] = []
    else:
        payload["severity"] = [s.strip()
                               for s in params.get('severity').split(",")]

    if not params.get('status'):
        payload["status"] = []
    else:
        payload["status"] = [s.strip()
                             for s in params.get('status').split(",")]

    if not params.get('idList'):
        payload["idList"] = []
    else:
        payload["idList"] = [s.strip()
                             for s in params.get('idList').split(",")]

    if not params.get('alertType'):
        payload["alertType"] = []
    else:
        payload["alertType"] = [s.strip()
                                for s in params.get('alertType').split(",")]

    if not params.get('countryList'):
        payload["countryList"] = []
    else:
        payload["countryList"] = [s.strip()
                                  for s in params.get('countryList').split(",")]

    if not params.get('asc'):
        payload["asc"] = ""
    else:
        payload["asc"] = params.get('asc')

    if not params.get('desc'):
        payload["desc"] = ""
    else:
        payload["desc"] = params.get('desc')

    endpoint = 'alert/list'

    if not config.get('resourceMap'):
        get_resource_url_map(config, params)

    resource_map = config.get('resourceMap')

    user_id = resource_map[0]['roleId']
    business_units = [bu for bu in resource_map[0]['buMapSet']]
    all_data = []
    for bu in business_units:
        additional_headers = {
            "companyId": str(bu['companyId']),
            "roleId": str(user_id),
            "buId": str(bu['buId']),
        }
        result = fetch_paginated_data(
            config=config, endpoint=endpoint, method='POST', data=payload, additional_headers=additional_headers)
        all_data.extend(result)

    # enrich the file data if possible
    files = []
    file_data = {}
    for file in [{"buId": alert_data["buId"], "companyId": alert_data["companyId"], "fileId": alert_data["fileId"]} for alert_data in all_data]:
        if file["fileId"] not in files:
            files.append(file["fileId"])
            params = {
                "companyId": str(file["companyId"]),
                "roleId": str(user_id),
                "buId": str(file["buId"]),
                "service": payload["service"],
                "fileId": str(file["fileId"])
            }
            file_summary = get_file_summary(config, params=params)
            file_data[file["fileId"]] = file_summary["data"]["fileSummary"]

    return {
        "alerts": all_data,
        "file_details": file_data,
    }


def search_activity(config, params):
    payload = {}
    params = build_params(params)
    if params:
        payload = payload | params
    if params.get('startTime'):
        # 2024-12-14T08:00:00.000Z
        payload['startTime'] = str(
            round(datetime.strptime(params.get('startTime'), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()) * 1000)
    else:
        now = datetime.utcnow()
        start_time = (now - timedelta(days=7)
                      ).strftime(f"%s%f")[:-3]
        payload['startTime'] = int(start_time)
    if params.get('endTime'):
        payload['endTime'] = str(
            round(datetime.strptime(params.get('endTime'), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()) * 1000)
    else:
        now = datetime.utcnow()
        end_time = now.strftime(f"%s%f")[:-3]
        payload['endTime'] = int(end_time)
    if params.get('skip'):
        payload['skip'] = int(params.get('skip'))
    else:
        payload['skip'] = 0
    if params.get('limit'):
        payload['limit'] = int(params.get('limit'))
    else:
        payload['limit'] = 100

    if params.get('cityList'):
        payload["cityList"] = [s.strip()
                               for s in params.get('cityList').split(",")]

    if params.get('idList'):
        payload["idList"] = [s.strip()
                             for s in params.get('idList').split(",")]

    if params.get('activity'):
        # translate activity names to ids
        for name in [s.strip() for s in params.get('activity').split(",")]:
            for activity in ACTIVITY_TYPES:
                if name in activity.values():
                    payload["activity"].append(activity["id"])

    if params.get('ipList'):
        payload["ipList"] = [s.strip()
                             for s in params.get('ipList').split(",")]

    if params.get('objectName'):
        payload["objectName"] = params.get('objectName')

    endpoint = 'activity/data'

    if not config.get('resourceMap'):
        get_resource_url_map(config, params)

    resource_map = config.get('resourceMap')

    user_id = resource_map[0]['roleId']
    business_units = [bu for bu in resource_map[0]['buMapSet']]
    all_data = []
    for bu in business_units:
        additional_headers = {
            "companyId": str(bu['companyId']),
            "roleId": str(user_id),
            "buId": str(bu['buId']),
            "service": params.get('service', "AWSS3")
        }
        result = fetch_paginated_data(
            config=config, endpoint=endpoint, method='POST', data=payload, additional_headers=additional_headers)
        all_data.extend(result)

    return {"activities": all_data}


def get_file_summary(config=None, params=None):
    fc = FortiCASB(config)
    params = build_params(params)

    additional_headers = {
        "companyId": params.get('companyId', None),
        "roleId": params.get('roleId', None),
        "buId": params.get('buId', None),
        "service": params.get('service', None),
        "fileId": params.get('fileId', None),
        "timezone": params.get('timezone', "-0800")
    }

    result = fc.make_api_call(
        config=config, endpoint="profile/document/fileSummary", method='POST', data='{}', additional_headers=additional_headers)
    return result


def get_resource_url_map(config=None, params=None):
    fc = FortiCASB(config)
    params = build_params(params)
    endpoint = f"resourceURLMap"
    response = fc.make_api_call(config=config, endpoint=endpoint)

    config['resourceMap'] = response

    return response


def fetch_paginated_data(config=None, endpoint=None, method='GET', data=None, additional_headers=None):
    fc = FortiCASB(config)
    all_data = []
    while True:
        result = fc.make_api_call(
            config=config, endpoint=endpoint, method=method, data=data, additional_headers=additional_headers)

        # Collect 'data' field
        result_data = result.get('data', [])
        if isinstance(result_data, list):
            all_data.extend(result_data)
        elif isinstance(result_data, dict):
            all_data.extend(result_data.get('datas', []))

        # Pagination details
        limit = result.get('limit', 10)
        skip = result.get('skip', 0)
        total_count = result.get('totalCount', 0)

        # Check if all records have been fetched
        if skip + limit >= total_count:
            break

        # Update the skip for the next page
        data['skip'] = skip + limit

    return all_data


def check_health(config):
    try:
        fc = FortiCASB(config)
        if not 'token' in config:
            token_resp = fc.generate_token()
            config['token'] = token_resp.get('access_token')
            config['expiresAt'] = token_resp.get('expires')
            connector_info = config.get('connector_info')
            update_connnector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                     config['config_id'])
            return True
        else:
            token_resp = fc.validate_token(config)
            return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'get_resource_url_map': get_resource_url_map,
    'search_alerts': search_alerts,
    'get_file_summary': get_file_summary,
    'search_activity': search_activity
}
