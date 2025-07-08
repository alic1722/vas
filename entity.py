# 定义统一的json返回的实体类
from flask import jsonify


class ResponseBase:
    def __init__(self, code, msg, data):
        self.code = code
        self.msg = msg
        self.data = data

    @staticmethod
    def success_msg(msg):
        obj = ResponseBase(200, msg, '')
        dict_obj = obj.to_dict()
        return jsonify(dict_obj)

    @staticmethod
    def success(msg, data):
        obj = ResponseBase(200, msg, data)
        dict_obj = obj.to_dict()
        return jsonify(dict_obj)

    @staticmethod
    def error(msg):
        obj = ResponseBase(400, msg, data='')
        dict_obj = obj.to_dict()
        return jsonify(dict_obj)

    def to_dict(self):
        return {'code': self.code, 'msg': self.msg, 'data': self.data}
