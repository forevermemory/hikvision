import requests
import time
import uuid
from hashlib import sha256
import hmac
import base64

import json
from datetime import datetime

requests.packages.urllib3.disable_warnings()  # 取消警告


class HaikangHandle():
    '''
    HaikangHandle(app_key, secret, ip, port, protocol='https')\n
    app_key: 海康平台的key\n
    secret: 密钥\n
    ip: server ip\n
    port: port\n
    protocol: default https 
    '''

    __app_key = ''
    __secret = ''
    __api_ip = ''
    __api_port = 0
    __protocol = ''
    __headers = {}

    def __init__(self, app_key, secret, ip, port, protocol='https'):
        if app_key == '' or secret == '' or ip == '' or port == 0:
            raise Exception("请传入参数")
        self.__app_key = app_key
        self.__secret = secret
        self.__api_ip = ip
        self.__api_port = port
        self.__protocol = protocol

    def __get_base_header(self):
        self.__headers['X-Ca-Key'] = self.__app_key
        self.__headers['X-Ca-Nonce'] = str(uuid.uuid1())
        self.__headers['X-Ca-Timestamp'] = str(int(round(time.time() * 1000)))
        # print (int(t))                  #秒级时间戳
        # print (int(round(t * 1000)))    #毫秒级时间戳

        # 参与签名的头
        self.__get_header_sign_headers()
        self.__headers['Date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.__headers['X-Ca-Signature'] = "TODO"

    def __get_header_sign_headers(self):
        _a = sorted(self.__headers.items(), key=lambda x: x[0], reverse=False)
        _aa = dict(_a)
        _tmp_str_arr = []
        for key in _aa:
            _tmp_str_arr.append(key.lower())
        self.__headers['X-Ca-Signature-Headers'] = ','.join(_tmp_str_arr)

    def __get_sign(self, sign_url):
        self.__get_base_header()

        s = '''POST\n*/*\napplication/json\n'''
        try:
            x = self.__headers['Date']
            s += "%s\n" % x
        except Exception as _:
            pass
        s += '''x-ca-key:%s\n''' % (self.__app_key)
        try:
            x = self.__headers['X-Ca-Nonce']
            s += "x-ca-nonce:%s\n" % x
        except Exception as _:
            pass
        try:
            x = self.__headers['X-Ca-Timestamp']
            s += "x-ca-timestamp:%s\n" % x
        except Exception as _:
            pass

        s += sign_url  # 签名字符串
        # 以appSecret为密钥，使用HmacSHA256算法对签名字符串生成消息摘要，对消息摘要使用BASE64算法生成签名（签名过程中的编码方式全为UTF-8）
        key = self.__secret.encode('utf-8')
        message = s.encode('utf-8')
        sign = base64.b64encode(
            hmac.new(key, message, digestmod=sha256).digest())
        sign = str(sign, 'utf-8')
        # print(sign)
        self.__headers['X-Ca-Signature'] = sign

    def do_post(self, req_url, data):
        sign_url = '/artemis' + req_url
        # 计算签名

        self.__get_sign(sign_url)
        self.__headers['Method'] = "POST"
        self.__headers['Accept'] = "*/*"

        # 请求
        req_url = self.__protocol+"://"+self.__api_ip+":" + \
            str(self.__api_port)+"/artemis"+req_url
        res = requests.post(url=req_url, json=data,
                            headers=self.__headers, verify=False).text
        return res

    def get_rtsp_stream(self, camera_index_code):
        data = {
            "cameraIndexCode": camera_index_code,
            "streamType": 0,
            "protocol": "hls",
            "transmode": 1
        }
        res = self.do_post("/api/video/v2/cameras/previewURLs", data)
        return res

    def get_play_list(self):
        data = {
            "pageNo": 1,
            "pageSize": 1000,
        }

        res = self.do_post("/api/resource/v2/camera/search", data)
        return res


def main():
    # TODO 换成你自己的
    s = HaikangHandle('key', 'secret',
                      'ip', 1443, 'https')

    # res = s.get_play_list()
    # s.do_post(url,data) TODO
    res = s.get_rtsp_stream('externalIndexCode')

    print(res)


if __name__ == "__main__":
    main()
