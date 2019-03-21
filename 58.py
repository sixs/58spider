# encoding:utf-8
'''
desc: 58模拟登录 & 投递简历查看手机号
author: sixseven
date: 2019-03-21
contact: 2557692481@qq.com
'''

import requests
from copy import deepcopy
import time
import json
import demjson
import execjs
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import rsa
import binascii
import base64
import re
import os
from urllib.parse import quote

import config


class SpiderFor58():

    def __init__(self):

        self.username = config.LOGIN_INFO['username']
        self.password = config.LOGIN_INFO['password']
        self.basic_info = config.BASIC_INFO
        self.cookies_path = config.COOKIES_PATH
        self.encrypt_path = config.ENCRYPT_PATH

        # 加载cookies
        if os.path.exists(self.cookies_path):
            print('cookies存在，加载cookies')
            with open(self.cookies_path, encoding='utf-8', mode='r') as fp:
                cookies_str = fp.read()
                self.cookies = json.loads(cookies_str)
                if self.test_cookies():
                    print('cookies可用')
                else:
                    print('cookies不可用')
                    self.login()
        else:
            self.login()

    # 测试cookie
    def test_cookies(self):
        user_info_url = 'http://my.58.com/webpart/userbasicinfo'
        headers = {
            'Host': 'my.58.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
        }
        req = requests.get(user_info_url, headers=headers, cookies=self.cookies, allow_redirects=False)
        if req.status_code==200:
            return True
        elif req.status_code==302:
            return False
        else:
            print('未知错误，return_data: %s' % req.text)
            return False

    # 登录
    def login(self):

        print('登录开始')

        session = requests.session()
        headers = {
            'Host': 'passport.58.com',
            'Origin': 'http://passport.58.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
        }
        # 访问登陆页
        req1 = session.get('http://passport.58.com/login', headers=headers) 

        # 获取rsa加密所需的modulus和exponent

        print('获取modulus和exponent')

        token_url = 'http://passport.58.com/frontend/data?_=%s' % int(time.time()*1000)
        headers2 = deepcopy(headers)
        headers2['Referer'] = 'http://passport.58.com/login'
        req2 = session.get(token_url, headers=headers2)
        json_data2 = json.loads(req2.text)['data']

        rsaModulus = json_data2['rsaModulus']
        rsaExponent = json_data2['rsaExponent']

        # rsa加密密码

        print('密码加密')

        modulus = int(rsaModulus, 16)
        exponent = int(rsaExponent, 16)
        timespan = 1411093327735 - int(time.time()*1000)
        encrypt_str = '%s%s' % (timespan, quote(self.password))
        password = self.encrypt_password(encrypt_str, rsaModulus, rsaExponent)

        # 登录

        print('登录中')

        data = {
            'source': 'passport',
            'password': password,
            'timesign': '',
            'isremember': 'true',
            'callback': 'successFun',
            'yzmstate': '',
            'fingerprint': 'CE823427AB070C56376861FB864D2A96D18C6FD974329DF6_011',
            'path': 'https://my.58.com/pro/persondata/?pts=1553083809285',
            'finger2': 'zh-CN|24|1|4|1366_768|1366_738|-480|1|1|1|undefined|1|unknown|Win32|unknown|3|false|false|false|false|false|0_false_false|d41d8cd98f00b204e9800998ecf8427e|63a8899c6b5224fcf16cd457db5c29c9',
            'username': self.username,
            'validcode': '',
            'vcodekey': '',
            'btnSubmit': '登录中...',
        }
        req3 = session.post(url='https://passport.58.com/login/pc/dologin', headers=headers, data=data, allow_redirects=False)
        if req3.headers.get('Set-Cookie') and 'PPU' in req3.headers['Set-Cookie']:
            print('登录成功')
            with open('./cookies.txt', encoding='utf-8', mode='w') as fp:
                self.cookies = json.dumps(session.cookies.get_dict())
                fp.write(self.cookies)
                print('保存cookies')
        else:
            print('登陆失败')
            print(req3.headers)
            print(req3.text)


    # 创建简历并投递
    def micro(self, job_url):

        print('创建简历并投递简历')

        headers = {
            'Host': 'jianli.58.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36'
        }
        params_str = job_url.split('?')[1]
        params_list = params_str.split('&')
        params_dict = {}
        for params in params_list:
            split_obj = params.split('=')
            params_dict[split_obj[0]] = split_obj[1]

        # 验证是否投递

        print('验证是否投递简历')

        delivery_check = 'https://jianli.58.com/wresume/ajaxislowinfo/%s?_=%s' % (
                params_dict['entinfo'][:-2],
                int(time.time()*1000)
            )
        headers1 = deepcopy(headers)
        req1 = requests.get(delivery_check, headers=headers1, cookies=self.cookies)
        return_message = json.loads(req1.text)['returnMessage']
        json_data1 = demjson.decode(return_message)
        if json_data1['deliveryCount']:
            print('已投递简历')
            return True

        # 查询是否存在对应类型简历

        print('查询是否存在对应类型简历')

        resume_check = 'https://jianli.58.com/resumedelivery/check'
        headers2 = deepcopy(headers)
        headers2['Referer'] = job_url
        query_params2 = {
            'infoId': params_dict['entinfo'][:-2],
            'fromurl': job_url,
            '_': int(time.time()*1000)
        }
        req2 = requests.get(resume_check, headers=headers2, params=query_params2, cookies=self.cookies)
        json_data2 = json.loads(req2.text)
        resume_is_exists = False 
        try:
            resume_id = json_data2['data']['resumeId']
            resume_is_exists = True
            print('简历已存在，resume_id: %s' % resume_id)
        except:
            print('简历不存在，新建简历')


        if not resume_is_exists:    # 简历不存在，新建简历
            # 创建简历pre准备

            print('获取page_json和crsf_token')

            pre_url = 'https://jianli.58.com/resumepost/createmicro'
            headers3 = deepcopy(headers)
            query_params3 = {
                'infoId': params_dict['entinfo'][:-2],
                'itype': 1,
                'fromType': 1,
                'role': '',
                'psid': params_dict['psid'],
                'deliverySource': 1,
                'finalCp': params_dict['finalCp'],
                'tjFrom': '#/'
            }
            req3 = requests.get(pre_url, headers=headers3, params=query_params3, cookies=self.cookies)
            
            match_obj = re.findall(r'____global\.pageJson\s*\=\s*({.*?});\s*____global\.csrfToken\s*=\s*\"(.*?)\"', 
                req3.text)
            if match_obj:
                page_json = json.loads(match_obj[0][0])
                crsf_token = match_obj[0][1]

                # 创建简历

                print('创建简历')

                micro_url = 'https://jianli.58.com/resumepost/micro'
                headers5 = deepcopy(headers)
                headers5['Origin'] = 'https://jianli.58.com'
                info_json = self.basic_info
                data5 = dict(page_json, **info_json)
                req5 = requests.post(micro_url, headers=headers5, data=data5, cookies=self.cookies)
                json_data5 = json.loads(req5.text)
                if json_data5.get('code')==13000029:
                    print('创建简历失败，出现滑块验证码，return_data: %s' % json_data5)
                    return False
                print('创建简历成功，return_data:%s' % json_data5)

            else:
                print('匹配page_json和crsf_token失败，return_data: %s' % req3.text)
                return False

        # 投递简历

        print('投递简历')

        process_micro = 'https://jianli.58.com/resumedelivery/process'
        headers6 = deepcopy(headers)
        headers6['Referer'] = job_url
        query_params6 = {
            'infoId': params_dict['entinfo'][:-2],
            'resumeId': resume_id,
            'deliverySource': 1,
            'tjFrom': '',
            'finalCp': params_dict['finalCp'],
            'role': '',
            'fromUrl': job_url,
            '_': int(time.time())
        }
        req6 = requests.get(process_micro, headers=headers6, params=query_params6, cookies=self.cookies)
        json_data6 = json.loads(req6.text)
        if json_data6.get('code')==12000011:
            print('投递成功')
            return True
        else:
            print('投递失败，json_data：%s' % json_data6)
            return False


    # 获取电话信息
    def getNumber(self, job_url):

        print('获取招聘单位电话')

        params_str = job_url.split('?')[1]
        params_list = params_str.split('&')
        params_dict = {}
        for params in params_list:
            split_obj = params.split('=')
            params_dict[split_obj[0]] = split_obj[1]
        url = 'https://zpservice.58.com/numberProtection/biz/pcBindV2?infoId=%s' % params_dict['entinfo'][:-2]
        headers = {
            'Host': 'zpservice.58.com',
            'Referer': job_url,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36'
        }
        req = requests.get(url, headers=headers, cookies=self.cookies)
        json_data = json.loads(req.text)
        if not 'virtualNum' in json_data:
            print('获取电话失败，return_data: %s' % json_data)
        else:
            if json_data.get('virtualNum'):
                phone = self.decrypt_number(json_data['virtualNum'])
                print(phone)
            else:
                print(json_data['tips'])

    # 密码加密
    def encrypt_password(self, encrypt_str, rsaModulus, rsaExponent):
        # # 方法一：python RSA加密（不可用）
        # modulus = int(rsaModulus, 16)
        # exponent = int(rsaExponent, 16)
        # key = rsa.PublicKey(modulus, exponent)
        # return str(
        #       binascii.b2a_hex(
        #           rsa.encrypt(bytes(encrypt_str, encoding='utf-8'), key),
        #       ), 
        #       encoding='utf-8'
        #   )

        # 方法二：调用js加密
        with open(self.encrypt_path, encoding='utf-8', mode='r') as fp:
            js = fp.read()
        ctx = execjs.compile(js)
        return ctx.call("encryptString", encrypt_str, rsaExponent, rsaModulus)


    # 虚拟电话解密(AES解密)
    def decrypt_number(self, encrypt_number):
        encrypt_number = base64.b64decode(encrypt_number)
        key = bytes('RIOHwmVrvD+tt8Xv', encoding = "utf8")
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(encrypt_number).decode("utf-8")[:11]


if __name__ == '__main__':
    spiderFor58 = SpiderFor58()
    # job_url = 'https://bj.58.com/zhuanye/25439271143092x.shtml?adtype=1&finalCp=000001230000000000000000000000000000_145859061203575297842326198&entinfo=25439271143092_q&adact=3&psid=145859061203575297842326198&ytdzwdetaildj=2'
    # spiderFor58.micro(job_url)
    # spiderFor58.getNumber(job_url)