import http.client
import requests
import json
import logging
import socket
from logging.handlers import SysLogHandler
from LogStream import storage_engine
from urllib.parse import urlencode
from time import gmtime, strftime

class F5CSGeneric (storage_engine.DatabaseFormat):
    def __init__(self, username, password, logger, host='api.cloudservices.f5.com'):
        super(F5CSGeneric, self).__init__(logger)
        # Table
        self.type = 'f5_cloud_services'
        # Primary key
        self.id = username
        # Relationship with other tables
        self.children['log'] = {}
        self.logs = self.children['log'].values()
        # Attribute
        self.host = host
        self.username = username
        self.password = password
        self.session = None
        self.access_token = None
        self.refresh_token = None
        self.primary_account_id = None
        self.catalog_id = None
        self.service_type = None
        self.get_token()
        self.get_account_user()

    def generate_error(self, r):
        if self.logger:
            self.logger.error('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))
        raise ConnectionError('%s::%s: code %s; %s' %
                              (__class__.__name__, __name__, r.status_code, r.text))

    def _get(self, path, parameters=None):
        # URL builder
        if parameters and len(parameters) > 0:
            uri = path + '?' + '&'.join(parameters)
        else:
            uri = path

        url = 'https://' + self.host + uri
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        r = self.session.get(
            url,
            headers=headers,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        return r.json()

    def _post(self, path, data):
        url = 'https://' + self.host + path
        headers = {
            'Authorization': 'Bearer ' + self.access_token,
            'Content-Type': 'application/json'
        }
        r = self.session.post(
            url,
            headers=headers,
            json=data,
            verify=False)
        if r.status_code not in (200, 201, 202, 204):
            self.generate_error(r)

        if r.text == '':
            return {}
        else:
            return r.json()

    def get_token(self):
        self.session = requests.session()
        url = 'https://' + self.host + '/v1/svc-auth/login'
        headers = {
            'Referer': url,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'username': self.username,
            'password': self.password
        }
        r = self.session.post(
            url,
            headers=headers,
            data=data,
            verify=False)
        if self.logger:
            self.logger.info('Create Token for an Application using Password grant type associated to username %s' % (
                self.username))
        if r.status_code != requests.codes.ok:
            if self.logger:
                self.logger.error('%s::%s: code %s; %s' %
                                  (__class__.__name__, __name__, r.status_code, r.text))
            raise
        else:
            self.access_token = r.json()['access_token']
            self.refresh_token = r.json()['refresh_token']

    def get_account_user(self):
        path = '/v1/svc-account/user'
        parameters = []
        self.primary_account_id = self._get(path, parameters)

    def get_subscription(self):
        path = '/v1/svc-subscription/subscriptions'
        parameters = [
            'catalogId=' + self.catalog_id,
            'account_id=' + self.primary_account_id,
            'service_type=' + self.service_type,
        ]
        return self._get(path, parameters)


class F5CSEAPInstance (F5CSGeneric):
    def __init__(self, subscription, username, password, logger):
        super(F5CSEAPInstance, self).__init__(subscription, username, password, logger)
        # Table
        self.type = 'eap'
        # Primary key
        self.id = subscription['subscription_id']
        # Attribute
        self.subscription_id = subscription['subscription_id']
        self.service_instance_id = subscription['service_instance_id']
        self.service_instance_name = subscription['service_instance_name']
        self.time_fetch_security_events = self._update_time()
        self.events = []

    def _update_time(self):
        return strftime("%Y-%m-%dT%H:%M:%SZ", gmtime())

    def fetch_security_events(self):
        url = '/api/v2/analytics/security/events'
        data = {
            'service_instance_id': self.service_instance_id,
            'subscription_id': self.subscription_id,
            'since': self.time_fetch_security_events
        }
        self.time_fetch_security_events = self._update_time()
        self.events += self._post(url, data)['events']

    def pop_security_events(self):
        data = {
            'service_instance_name': self.service_instance_id,
            'events': self.events
        }
        self.events = []
        return data


class F5CSEAP (F5CSGeneric):
    def __init__(self, username, password, logger):
        super(F5CSEAP, self).__init__(username, password, logger)
        # Table
        self.type = 'eap'
        # Primary key
        self.id = username
        # Relationship with other tables
        self.children['eap_instance'] = {}
        self.eap_instances = self.children['eap_instance'].values()
        # Attribute
        self.service_type = 'waf'
        self.catalog_id = 'c-aa9N0jgHI4'

    def fecth_subscriptions(self):
        subscriptions = self.get_subscription()['subscriptions']
        cur_subscriptions = []

        # CREATE new eap_instance
        for subscription in subscriptions:
            if subscription not in self.eap_instances:
                eap_instance = F5CSEAPInstance(subscription, self.username, self.password, self.logger)
                self.create_child(eap_instance)
            cur_subscriptions.append(subscription['subscription_id'])

        # DELETE old eap_instance
        for eap_instance in self.eap_instances:
            if eap_instance.subscription_id not in cur_subscriptions:
                eap_instance.delete()

    def fetch_security_events(self):
        for eap_instance in self.eap_instances:
            eap_instance.fetch_security_events()

    def pop_security_events(self):
        events = []
        for eap_instance in self.eap_instances:
            events.append(eap_instance.pop_security_events())






        class ContextFilter(logging.Filter):
            hostname = socket.gethostname()

            def filter(self, record):
                record.hostname = ContextFilter.hostname
                return True

        syslog = SysLogHandler(address=('(syslog.server)', syslog_port))
        syslog.addFilter(ContextFilter())

        format = '%(asctime)s %(hostname)s YOUR_APP: %(message)s'
        formatter = logging.Formatter(format, datefmt='%b %d %H:%M:%S')
        syslog.setFormatter(formatter)

        logger = logging.getLogger()
        logger.addHandler(syslog)
        logger.setLevel(logging.INFO)

        # jsondata = "{'date_time': '2020-06-12T16:50:20Z', 'geo_latitude': 52.3861, 'geo_longitude': 4.62463,
        #             'geo_country': 'netherlands',
        #             'detection_events': ['Access from malicious IP address', 'Violation Rating Threat detected'],
        #             'support_id': '554a9ed2e07fb794dd3986103ea524cd00869821326238465857', 'response_code': '',
        #             'source_ip': '77.250.227.202', 'method': 'GET', 'protocol': 'HTTPS', 'query_string': '',
        #             'sig_ids': [''], 'sig_names': [''], 'attack_types': ['Non-browser Client'],
        #             'ip_address_intelligence': 'Spam Sources', 'src_port': '56938', 'sub_violations': [''],
        #             'uri': '/2007/04/02/presented-at-the-ohio-information-security-forum/',
        #             'request': 'GET /2007/04/02/presented-at-the-ohio-information-security-forum/ HTTP/1.0\\r\\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\\r\\nUser-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36 Kinza/4.9.1\\r\\nReferer: https://www.michaelearls.com/2007/04/02/presented-at-the-ohio-information-security-forum/\\r\\nHost: www.michaelearls.com\\r\\nConnection: close\\r\\n',
        #             'violation_details': '[{\n\t"type": "MALICIOUS_IP",\n\t"details": {\n\n\t}\n}]', 'header': '',
        #             'violation_rating': '5', 'threat_campaign_names': '', 'fragment': '', 'request_status': 'Blocked',
        #             'severity': 'Critical', 'category': ['MALICIOUS_IP', 'HIGH_RISK_ATTACK'], 'geo_country_code': 'NL',
        #             'geo_state': 'noord-holland', 'geo_city': 'haarlem', 'cloud_provider': 'aws', 'region': 'us-east-2',
        #             'cell_id': 'c2', 'threat_campaign_ids': '',
        #             'violation_details_json': [{'details': {}, 'type': 'MALICIOUS_IP'}}"

        #for key, value in data.items():
            ##print(key, ":", value)
         #   print("[data_time"])


        ##logger.info(jsondata)
        logger.info("This is a message.. ")



def main():
    login()
    GetAccountUser(token)
    ##GetAccountCatalog(primaryAccountID)
    ##GetWAFSubscription(primaryAccountID)
    GetEAPSecurityEvents()
    ##GetEAPSecurityEvents(token)

main()
