F5 Cloud Services – LogStream
===========================


## Overview

The purpose of this project is to allow the ability to download F5 Cloud Services Essential App Protect (EAP) logs in real-time and steam the data to mulitple-log services. The LogSteam service is software hosted on a VM and/or docker image and does not store persistent logs.

### The flow is as:
Replace with image

###
The LogStream project requires basic account information, remote syslog server and port to be defined in the declaration.json file located within the LogStream folder. We have placed a sample file in the default directory for your reference.

delclaration.json
```json
{
    "f5cs": {
        "password": "PASSWORD",
        "username": "email address"
    },
    "logcollector": {
        "syslog": [
            {
                "ip_address": "x.x.x.x",
                "port": 514
            }
        ]
    }
}
```

### Support for Multiple EAP Instances
The LogStream agent will pull your catalog under your organization and build a list of all the EAP instances you are subscribed to. The EAP instances have a defined valued that will be refereced within the LogStream agent to pull the correct log files and defined FQDN.  
```json
{
            'service_instance_id': self.service_instance_id,
            'subscription_id': self.subscription_id,
            'since': self.time_fetch_security_events
            }
```


### Logging Format
The native format for EAP logs is json, we have parsed the logs giving the capability to define logger format.
```
attack_types, category, cloud_provider, date_time, detection_events, geo_city, geo_country, geo_country_code, geo_latitude, geo_longitude, geo_state, header, ip_address_intelligence, method, protocol, query_string, region, request_status, response_code, severity, sig_ids, sig_names, source_ip, src_port, sub_violations, support_id, threat_campaign_ids, threat_campaign_names, violation_details_json, violation_rating
```
