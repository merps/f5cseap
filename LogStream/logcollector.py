import logging
import socket
from logging.handlers import SysLogHandler
from LogStream import storage_engine
from urllib.parse import urlencode
from time import gmtime, strftime


class RemoteSyslog:
    def __init__(self, ip_address, port):
        self.handler = logging.handlers.SysLogHandler(address=(ip_address, port))

    def emit(self, messages):
        for message in messages:
            record = logging.makeLogRecord({
                'name': socket.gethostname(),
                'level': 1,
                'msg': message,
                'exc_info': 'exc_info'
            })
            self.handler.emit(record)


class LogCollector:
    def __init__(self, ip_address, port):
        self.handler = logging.handlers.SysLogHandler(address=(ip_address, port))

    def emit(self, messages):
        for message in messages:
            record = logging.makeLogRecord({
                'name': socket.gethostname(),
                'level': 1,
                'msg': message,
                'exc_info': 'exc_info'
            })
            self.handler.emit(record)
