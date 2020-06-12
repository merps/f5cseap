import http.client
import json
import logging
import socket
from logging.handlers import SysLogHandler

from urllib.parse import urlencode

f5saasUsername = "(username)"
f5saasPassword = "(password)"

def login():
    '''
    :param server:
    :param f5saasUsername:
    :param f5saasPassword:
    :return: Function to Login to the F5 Cloud SaaS portal and return a valid session token.
    '''
    global token
    conn = http.client.HTTPSConnection("api.cloudservices.f5.com")
    headers = {'content-type': "application/x-www-form-urlencoded"}
    logindetails = {'username': ''+f5saasUsername+'', 'password': ''+f5saasPassword+''}
    logindetails_data = json.dumps(logindetails)
    conn.request("POST", "/v1/svc-auth/login", logindetails_data, headers)
    response = conn.getresponse()
    raw_data = response.read()
    encoding = response.info().get_content_charset('utf8')  # JSON default
    data = json.loads(raw_data.decode(encoding))
    token = data["access_token"]
    return token

def GetAccountUser(token):
    '''
        :param token:
        :return: Function to login using the Bearer token and pull the Primary Account ID.
    '''
    global primaryAccountID
    conn = http.client.HTTPSConnection("api.cloudservices.f5.com")
    headers = {'content-type': 'application/json', 'Authorization': 'Bearer ' + token +''}
    ##print(headers)
    payload = {
    }
    conn.request("GET", "/v1/svc-account/user", payload, headers)
    response = conn.getresponse()
    ##print(response.status)
    raw_data = response.read()
    ##print(raw_data.decode("utf-8"))

    encoding = response.info().get_content_charset('utf8') # JSON Format
    data = json.loads(raw_data.decode(encoding))
    primaryAccountID = data["primary_account_id"]
    return primaryAccountID



def GetAccountCatalog(primaryAccountID):
    ##print(token)
    conn = http.client.HTTPSConnection("api.cloudservices.f5.com")
    headers = {'content-type': 'application/json', 'Authorization': 'Bearer ' + token +''}
    ##print(headers)
    payload = {
    }
    conn.request("GET", "/v1/svc-account/accounts/"+primaryAccountID+"/catalogs", payload, headers)
    response = conn.getresponse()
    ##print(response.status)
    raw_data = response.read()
    ##print(raw_data.decode("utf-8"))
    encoding = response.info().get_content_charset('utf8') # JSON Format
    data = json.loads(raw_data.decode(encoding))
    print(json.dumps(data, indent=2, sort_keys=True))

def GetWAFSubscription(primaryAccountID):
    ##print(token)
    conn = http.client.HTTPSConnection("api.cloudservices.f5.com")
    headers = {'content-type': 'application/json', 'Authorization': 'Bearer ' + token +''}
    ##print(headers)
    payload = {
    }
    conn.request("GET", "/v1/svc-subscription/subscriptions?account_id="+primaryAccountID+"&service_type=waf", payload, headers)
    response = conn.getresponse()
    ##print(response.status)
    raw_data = response.read()
    ##print(raw_data.decode("utf-8"))
    encoding = response.info().get_content_charset('utf8') # JSON Format
    data = json.loads(raw_data.decode(encoding))
    print(json.dumps(data, indent=2, sort_keys=True))

def GetEAPSecurityEvents():
    conn = http.client.HTTPSConnection("api.cloudservices.f5.com")
    headers = {'content-type': 'application/json', 'Authorization': 'Bearer ' + token +''}
    raw_payload = {
    "service_instance_id": "(WAFID)",
    "subscription_id": "(SUBID)",
    "since": "2020-06-12T09:02:28Z"
    }
    payload = json.dumps(raw_payload)
    conn.request("POST", "/waf/v1/analytics/security/events", payload, headers)
    response = conn.getresponse()
    raw_data = response.read()
    encoding = response.info().get_content_charset('utf8') # JSON Format
    data = json.loads(raw_data.decode(encoding))
    print(json.dumps(data, indent=2, sort_keys=True))

    ## add in syslog


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
