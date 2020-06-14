from flask import (Flask, request)
from flask_restful import (Api, Resource)
from flasgger import Swagger
from LogStream import f5cloudservices, logcollector
import logging
import threading
import uuid

application = Flask(__name__)
api = Api(application)
swagger = Swagger(application)


def setup_logging(log_level, log_file):
    if log_level == 'debug':
        log_level = logging.DEBUG
    elif log_level == 'verbose':
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    return logging.getLogger(__name__)


# Global var
logger = setup_logging(
    log_level='debug',
    log_file='logs/log.txt'
)

f5cs = f5cloudservices.F5CSEAP(
    username=None,
    password=None,
    logger=logger
)

logcol_db = logcollector.LogCollectorDB(logger)

thread_manager = {
    'event': threading.Event(),
    'thread_queue': []
}


@swagger.definition('f5cs', tags=['v2_model'])
class ConfigF5CS:
    """
    Recommendation Query Context
    ---
    required:
      - username
      - password
    properties:
      username:
        type: string
        description: F5 CS user account
      password:
        type: string
        description: password
    """

    @staticmethod
    def prepare(data_json):
        if 'username' in data_json and 'password' in data_json:
            result = {
                'code': 200,
                'object': data_json
            }
        else:
            result = {
                'code': 400,
                'msg': 'parameters: username, password must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        f5cs.username = data_json['object']['username']
        f5cs.password = data_json['object']['password']
        f5cs.enable()
        f5cs.fecth_subscriptions()

    @staticmethod
    def get():
        if f5cs is not None:
            return f5cs.get()
        else:
            return None


@swagger.definition('logcollector', tags=['v2_model'])
class ConfigLogCollector:
    """
    Recommendation Query Context
    ---
    required:
      - syslog
    properties:
        syslog:
          type: array
          items:
            type: object
            schema:
            $ref: '#/definitions/syslog_server'
    """

    @staticmethod
    def prepare(data_json):
        if 'syslog' in data_json.keys():
            result = []
            code = 0
            for instance in data_json['syslog']:
                data = ConfigSyslogServer.prepare(instance)
                result.append(data)
                code = max(code, data['code'])
            result = {
                'code': code,
                'syslog': result
            }
        else:
            result = {
                'code': 400,
                'msg': 'parameters: syslog must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        for instance in data_json['syslog']:
            ConfigSyslogServer.set(instance)

    @staticmethod
    def get():
        return logcol_db.get()


@swagger.definition('syslog_server', tags=['v2_model'])
class ConfigSyslogServer:
    """
    Recommendation Query Context
    ---
    required:
      - ip_address
      - port
    properties:
      ip_address:
        type: string
        pattern: '^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$'
        description: ipv4 address
        example:
          1.1.1.1
      port:
        type: integer
        description: port listener
        default: 514
    """

    @staticmethod
    def prepare(data_json):
        if 'ip_address' in data_json.keys():
            result = {
                'code': 200,
                'object': {
                    'ip_address': data_json['ip_address']
                }
            }
            if 'port' in data_json.keys():
                result['object']['port'] = data_json['port']
            else:
                result['object']['port'] = 514
        else:
            result = {
                'code': 400,
                'msg': 'parameters: log_level, log_file must be set'
            }
        return result

    @staticmethod
    def set(data_json):
        logcol_db.add(logcollector.RemoteSyslog(
            ip_address=data_json['object']['ip_address'],
            port=data_json['object']['port'],
            logger=logger)
        )


class Declare(Resource):
    def get(self):
        """
        Get LogStream current declaration
        ---
        tags:
          - F5 Cloud Services LogStream
        responses:
          200:
            schema:
              required:
                - f5cs
                - logcollector
              properties:
                f5cs:
                  type: object
                  schema:
                  $ref: '#/definitions/f5cs'
                logcollector:
                  type: object
                  schema:
                  $ref: '#/definitions/logcollector'
        """
        return {
            'f5cs': ConfigF5CS.get(),
            'logcollector': ConfigLogCollector.get(),
        }, 200

    def post(self):
        """
        Configure LogStream in one declaration
        ---
        tags:
          - F5 Cloud Services LogStream
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            schema:
              required:
                - f5cs
                - logcollector
              properties:
                f5cs:
                  type: object
                  schema:
                  $ref: '#/definitions/f5cs'
                logcollector:
                  type: object
                  schema:
                  $ref: '#/definitions/logcollector'
        responses:
          200:
            description: Deployment done
         """
        data_json = request.get_json()
        result = {}

        # Sanity check
        cur_class = 'f5cs'
        if cur_class in data_json.keys():
            result[cur_class] = ConfigF5CS.prepare(data_json[cur_class])
            if result[cur_class]['code'] not in (200, 201, 202):
                return result, result[cur_class]['code']
        else:
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }

        cur_class = 'logcollector'
        if cur_class in data_json.keys():
            result[cur_class] = ConfigLogCollector.prepare(data_json[cur_class])
            if result[cur_class]['code'] not in (200, 201, 202):
                return result, result[cur_class]['code']
        else:
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }

        # Deploy
        cur_class = 'f5cs'
        if cur_class in result.keys():
            ConfigF5CS.set(result[cur_class])

        cur_class = 'logcollector'
        if cur_class in result.keys():
            ConfigLogCollector.set(result[cur_class])

        return "Configuration done", 200


class EngineThreading(Resource):
    @staticmethod
    def start_main():
        if len(thread_manager['thread_queue']) == 0:
            t = threading.Thread(
                target=EngineThreading.task_producer_consumer,
                name=str(uuid.uuid4()),
                args=(thread_manager['event'],)
            )
            thread_manager['thread_queue'].append(t)
            logger.info("%s::%s: NEW THREAD, database changes will be sync by the new thread in sync_queue: id=%s" %
                        (__class__.__name__, __name__, t.name))

            t.start()

    @staticmethod
    def task_producer_consumer():
        f5cs.fetch_security_events()
        events = f5cs.pop_security_events()
        logcol_db.emit(events)


class Engine(Resource):
    def get(self):
        """
        Get engine status
        ---
        tags:
          - F5 Cloud Services LogStream
        responses:
          200:
            schema:
              required:
                - status
              properties:
                status:
                  type: string
                  description: status
                threads:
                  type: integer
                  description: number of running threads
        """
        data = {}
        if len(thread_manager['thread_queue']) > 0:
            data['status'] = 'sync processing'
            data['threads'] = thread_manager['thread_queue'].len()
        else:
            data['status'] = 'no sync process'
        return data

    def post(self):
        """
            Start/Stop engine
            ---
            tags:
              - F5 Cloud Services LogStream
            consumes:
              - application/json
            parameters:
              - in: body
                name: body
                schema:
                  required:
                    - action
                  properties:
                    f5cs:
                      type: string
                      description : Start/Stop engine
            responses:
              200:
                description: Action done
        """
        data_json = request.get_json()

        # Sanity check
        cur_class = 'action'
        if cur_class not in data_json.keys():
            return {
                'code': 400,
                'msg': 'parameters: ' + cur_class + ' must be set'
            }
        else:
            # Sanity check
            if data_json[cur_class].lower() == 'start':
                if len(thread_manager['thread_queue']) > 0:
                    return {
                        'code': 400,
                        'msg': 'engine already started'
                    }
                else:
                    EngineThreading.task_producer_consumer()
            elif data_json[cur_class].lower() == 'stop':
                if len(thread_manager['thread_queue']) == 0:
                    return {
                        'code': 400,
                        'msg': 'engine already stopped'
                    }
                else:
                    # STOP
                    pass


api.add_resource(Declare, '/declare')
api.add_resource(Engine, '/engine')

# Start program
if __name__ == '__main__':
    print("Dev Portal: http://127.0.0.1:5000/apidocs/")
    application.run(
        host="0.0.0.0",
        debug=True,
        use_reloader=True,
        port=5000
    )

