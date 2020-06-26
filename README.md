F5 Cloud Services – LogStream
===========================


## Overview

The purpose of this project is to allow the ability to download F5 Cloud Services Essentail App Protect (EAP) logs in real-time and steam the data to mulitple-log services. The LogSteam service is software hosted on a VM and/or docker image and does not store persistent logs.

### The flow is as:
Replace with image

###
The LogStream project requires basic account information, remote syslog server and port to be defined in the declaration.json file located within the LogStream folder. We have placed a sample file in the default directory for your reference.

delclaration.json
```
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

