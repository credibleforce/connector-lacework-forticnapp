""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from time import time
from datetime import datetime
from .constants import *
from connectors.core.utils import update_connector_config
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('fortinet-forticnapp')


class Lacework:
    def __init__(self, config):
        self.server_url = config.get('server_url').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url
        self.key_id = config.get('keyId')
        self.secret = config.get('secret')
        self.verify_ssl = config.get('verify_ssl')

    def convert_ts_epoch(self, ts):
        datetime_object = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
        return datetime_object.timestamp()

    def generate_token(self):
        try:
            data = {
                "keyId": self.key_id,
                "expiryTime": 86400
            }
            resp = self.make_api_call(
                endpoint="access/tokens", method="POST", data=data, is_token_call=True)
            return resp
        except Exception as err:
            logger.error("{0}".format(err))
            raise ConnectorError("{0}".format(err))

    def validate_token(self, connector_config):
        ts_now = time()
        if not connector_config.get('token'):
            logger.error(
                'Error occurred while connecting server: Unauthorized')
            raise ConnectorError(
                'Error occurred while connecting server: Unauthorized')
        expires = connector_config['expiresAt']
        expires_ts = self.convert_ts_epoch(expires)
        if ts_now > float(expires_ts):
            logger.info("Token expired at {0}".format(expires))
            token_resp = self.generate_token()
            connector_config['token'] = token_resp['token']
            connector_config['expiresAt'] = token_resp['expiresAt']
            connector_info = connector_config.get('connector_info')
            update_connector_config(connector_info['connector_name'], connector_info['connector_version'],
                                    connector_config,
                                    connector_config['config_id'])

            return "Bearer {0}".format(connector_config.get('token'))
        else:
            logger.info("Token is valid till {0}".format(expires))
            return "Bearer {0}".format(connector_config.get('token'))

    def make_api_call(self, config=None, endpoint=None, params=None, method='GET', data=None, is_token_call=False, is_next_page=False):
        if is_next_page:
            url = endpoint
        else:
            url = '{0}{1}{2}'.format(self.server_url, '/api/v2/', endpoint)
        logger.info('Request URL {0}'.format(url))
        if is_token_call:
            headers = {
                "X-LW-UAKS": self.secret
            }
        else:
            token = self.validate_token(config)
            headers = {
                'Authorization': token
            }
        try:
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
        except requests.exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except requests.exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except requests.exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except requests.exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError(
                'There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))

    def get_all_records(self, config, resp):
        result = resp.get('data')
        while resp.get('paging').get('urls').get('nextPage'):
            resp = self.make_api_call(config=config, endpoint=resp.get(
                'paging').get('urls').get('nextPage'), is_next_page=True)
            result.extend(resp.get('data'))
        return result


def build_params(params):
    return {k: v for k, v in params.items() if v is not None and v != ''}


def build_filters(params, filter_params):
    result = []
    for param_name, param_value in params.items():
        if param_name in filter_params:
            result.append({
                "expression": "eq",
                "field": param_name,
                "value": param_value
            })
    return result


def str_to_list(param):
    if ',' in param:
        return [item.strip() for item in param.split(',')]
    return [param.strip()]


def lql_query(config, params):
    lw = Lacework(config)
    payload = {}
    params = build_params(params)
    arguments = []
    if params.get('query'):
        query = {}
        query["queryText"] = params.get('query')
        payload['query'] = query
    if params.get('limit'):
        options = {}
        options["limit"] = params.get('limit')
        payload['options'] = options
    if params.get('startTime'):
        argument = {}
        argument['name'] = 'StartTimeRange'
        argument['value'] = params.get('startTime')
        arguments.append(argument)
    if params.get('endTime'):
        argument = {}
        argument['name'] = 'EndTimeRange'
        argument['value'] = params.get('endTime')
        arguments.append(argument)

    if arguments:
        payload["arguments"] = arguments

    endpoint = 'Queries/execute'
    response = lw.make_api_call(
        config=config, endpoint=endpoint, method='POST', data=payload)

    return response.get('data')


def search_host_vulnerabilities(config, params):
    lw = Lacework(config)
    filter_params = ["vulnId", "packageStatus",
                     "props.kernel_status", "riskInfo.host_risk_factors_breakdown.internet_reachability",
                     "riskInfo.host_risk_factors_breakdown.exploit_summary.exploit_public", "machineTags.Account",
                     "machineTags.TenantId", "machineTags.SubscriptionId",
                     "machineTags.ProjectId", "machineTags.InstanceId",
                     "machineTags.AmiId", "machineTags.Hostname",
                     "machineTags.Name", "fixInfo.fix_available", "severity"]
    payload = {}
    params = build_params(params)
    filters = build_filters(params, filter_params)
    if filters:
        payload['filters'] = filters
    timeFilter = {}
    if params.get('startTime'):
        timeFilter['startTime'] = params.get('startTime')
    if params.get('endTime'):
        timeFilter['endTime'] = params.get('endTime')
    if timeFilter:
        payload['timeFilter'] = timeFilter
    if params.get('returns'):
        payload['returns'] = str_to_list(params.get('returns'))
    endpoint = 'Vulnerabilities/Hosts/search'
    response = lw.make_api_call(
        config=config, endpoint=endpoint, method='POST', data=payload)
    if 'message' in response and response.get('message') == 'No content':
        return response
    return lw.get_all_records(config, response)


def search_container_vulnerabilities(config, params):
    lw = Lacework(config)
    filter_params = ["vulnId", "status", "severity", "packageStatus",
                     "imageRiskInfo.factors_breakdown.internet_reachability",
                     "imageRiskInfo.factors_breakdown.active_containers",
                     "imageRiskInfo.factors_breakdown.exploit_summary.exploit_public",
                     "imageId",
                     "fixInfo.fix_available"]
    payload = {}
    params = build_params(params)
    filters = build_filters(params, filter_params)
    if filters:
        payload['filters'] = filters
    timeFilter = {}
    if params.get('startTime'):
        timeFilter['startTime'] = params.get('startTime')
    if params.get('endTime'):
        timeFilter['endTime'] = params.get('endTime')
    if timeFilter:
        payload['timeFilter'] = timeFilter
    if params.get('returns'):
        payload['returns'] = str_to_list(params.get('returns'))
    endpoint = 'Vulnerabilities/Containers/search'
    response = lw.make_api_call(
        config=config, endpoint=endpoint, method='POST', data=payload)
    if 'message' in response and response.get('message') == 'No content':
        return response
    return lw.get_all_records(config, response)


def search_configuration(config, params):
    lw = Lacework(config)
    filter_params = ["account.AccountId", "account.projectId", "account.subscriptionId", "account.tenantId", "id", "region", "resource",
                     "severity", "status"]
    payload = {}
    params = build_params(params)
    filters = build_filters(params, filter_params)
    if filters:
        payload['filters'] = filters
    timeFilter = {}
    if params.get('startTime'):
        timeFilter['startTime'] = params.get('startTime')
    if params.get('endTime'):
        timeFilter['endTime'] = params.get('endTime')
    if timeFilter:
        payload['timeFilter'] = timeFilter
    if params.get('returns'):
        payload['returns'] = str_to_list(params.get('returns'))
    if params.get('dataset'):
        payload['dataset'] = params.get('dataset')
    endpoint = 'Configs/ComplianceEvaluations/search'
    response = lw.make_api_call(
        config=config, endpoint=endpoint, method='POST', data=payload)
    if 'message' in response and response.get('message') == 'No content':
        return response
    return lw.get_all_records(config, response)


def search_alerts(config, params):
    lw = Lacework(config)
    filter_params = ["alertId", "alertType", "severity",
                     "status", "subCategory", "category", "source"]
    payload = {}
    params = build_params(params)
    filters = build_filters(params, filter_params)
    if filters:
        payload['filters'] = filters
    timeFilter = {}
    if params.get('startTime'):
        timeFilter['startTime'] = params.get('startTime')
    if params.get('endTime'):
        timeFilter['endTime'] = params.get('endTime')
    if timeFilter:
        payload['timeFilter'] = timeFilter
    if params.get('returns'):
        payload['returns'] = str_to_list(params.get('returns'))
    endpoint = 'Alerts/search'
    response = lw.make_api_call(
        config=config, endpoint=endpoint, method='POST', data=payload)
    if 'message' in response and response.get('message') == 'No content':
        return response
    return lw.get_all_records(config, response)


def get_alert_details(config, params):
    lw = Lacework(config)
    endpoint = f"Alerts/{params.get('alertId')}?scope={params.get('scope')}"
    response = lw.make_api_call(config=config, endpoint=endpoint)
    return response


def get_alert_entities(config, params):
    lw = Lacework(config)
    endpoint = f"Alerts/Entities/{params.get('alertId')}"
    response = lw.make_api_call(config=config, endpoint=endpoint)
    return response


def get_alert_entity_details(config, params):
    lw = Lacework(config)
    endpoint = f"Alerts/EntityDetails/{params.get('alertId')}?contextEntityType={params.get('contextEntityType')}&entityValue={params.get('entityValue')}"
    response = lw.make_api_call(config=config, endpoint=endpoint)
    return response


def add_comment_to_alert(config, params):
    lw = Lacework(config)
    params = build_params(params)
    endpoint = f"Alerts/{params.pop('alertId')}/comment"
    response = lw.make_api_call(
        config=config, endpoint=endpoint, method='POST', data=params)
    return response


def close_alert(config, params):
    lw = Lacework(config)
    params = build_params(params)
    params['reason'] = REASON_FOR_CLOSING.get(params.get('reason'))
    endpoint = f"Alerts/{params.pop('alertId')}/close"
    response = lw.make_api_call(
        config=config, endpoint=endpoint, method='POST', data=params)
    return response


def check_health(config):
    try:
        lw = Lacework(config)
        if not 'token' in config:
            token_resp = lw.generate_token()
            config['token'] = token_resp.get('token')
            config['expiresAt'] = token_resp.get('expiresAt')
            connector_info = config.get('connector_info')
            update_connector_config(connector_info['connector_name'], connector_info['connector_version'], config,
                                    config['config_id'])
            return True
        else:
            token_resp = lw.validate_token(config)
            return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'lql_query': lql_query,
    'search_host_vulnerabilities': search_host_vulnerabilities,
    'search_container_vulnerabilities': search_container_vulnerabilities,
    'search_configuration': search_configuration,
    'search_alerts': search_alerts,
    'get_alert_details': get_alert_details,
    'get_alert_entities': get_alert_entities,
    'get_alert_entity_details': get_alert_entity_details,
    'add_comment_to_alert': add_comment_to_alert,
    'close_alert': close_alert
}
