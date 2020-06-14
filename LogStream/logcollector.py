import logging
import socket
from logging.handlers import SysLogHandler
from LogStream import storage_engine
from urllib.parse import urlencode
from time import gmtime, strftime


class RemoteSyslog(storage_engine.DatabaseFormat):
    def __init__(self, ip_address, port, logger):
        super(RemoteSyslog, self).__init__(logger)
        # Table
        self.type = 'syslog'
        # Primary key
        self.id = ip_address + ':' + port
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


class LogCollectorDB(storage_engine.DatabaseFormat):
    def __init__(self, logger):
        super(LogCollectorDB, self).__init__(logger)
        self.handlers = {}
        # Relationship with other tables
        self.children['syslog'] = {}

    def add(self, log_instance):
        if log_instance.id not in self.children[log_instance.type].keys():
            self.create_child(log_instance)

    def remove(self, log_instance):
        if log_instance.id in self.children[log_instance.type].keys():
            log_instance.delete()






