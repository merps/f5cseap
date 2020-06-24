F5 Cloud Services – LogStream
===========================


## Overview

The purpose of this project is to allow the ability to download F5 Cloud Services Essentail App Protect (EAP) logs in real-time and steam the data to mulitple-log services. The LogSteam service is software hosted on a VM and/or docker image and does not store persistent logs.

### The flow is as:

F5 Cloud Services EAP Generates logs in real-time 
==> Install LogStream Agent on local VM (Cloud, On-Prem) 
==> API Call over HTTPS Pulls logs from F5CS
==> LogSteam Agent will then push in syslog format to syslog type instances

