#!/usr/bin/python
# -*- coding: utf-8 -*-
# tencentcloud algorithem client example (using Version 3 signing) 
import hashlib
import hmac
import json
import time
from datetime import datetime
import requests


# 密钥参数(for用户修改)
secret_id = '71a0eddf562e58d43907'
secret_key = 'cc688bc810a4829ed4ddc6905f1d609eace152dc1998e09a769848a7c8ca5b47'

# 请求参数
method = 'POST'
service = 'asm'
host = '10.1.1.17:8088'
region = 'hz'
action = 'NotifyUserDelStage'
version = '2019-01-09'

print('-- starting cloud industry ai algo client --')
with open("data.json",'r') as load_f:
    data = json.load(load_f)

endpoint = 'http://' + host
request_parameters = json.dumps(data, separators=(',',':'), ensure_ascii=False, sort_keys= True)
print('-- step 1 -- read request body\n%s\n' % request_parameters)
# 计算签名摘要函数
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
# 获取派生密钥函数
def getSignatureKey(key, creDate, serviceName):
    kDate = sign(('TC3' + key).encode('utf-8'), creDate)
    kService = sign(kDate, serviceName)
    kSigning = sign(kService, 'tc3_request')
    return kSigning
# 获取当前时间戳，以及相应的UTC标准时间日期
timestamp = int(time.time())
credDate = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d')
# ************* 计算签名 START *************
# ************* 步骤 1: 创建规范请求串 *************
canonical_uri = '/'
canonical_querystring = ''
canonical_headers = 'content-type:application/json\n' + 'host:' + host + '\n'
signed_headers = 'content-type;host'
payload_hash = hashlib.sha256(request_parameters.encode("utf-8")).hexdigest()
print ('-- step 1.1 -- hashed payload:\n%s\n' % payload_hash)
canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
print ('-- step 2 -- create canonical request:\n%s\n' % canonical_request)
# ************* 步骤 2: 创建签名串*************
algorithm = 'TC3-HMAC-SHA256'
credential_scope = credDate + '/' + service + '/' + 'tc3_request'
string_to_sign = algorithm + '\n' +  str(timestamp) + '\n' +  credential_scope + '\n' +  hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
print ('-- step 3 -- create string to sign: \n%s\n' % string_to_sign)
# ************* 步骤 3: 计算签名 *************
# 计算派生签名密钥
signing_key = getSignatureKey(secret_key, credDate, service)
# 计算签名摘要
signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
# ************* 步骤 4: 签名信息添加到请求头部 Authorization *************
authorization_header = algorithm + ' ' + 'Credential=' + secret_id + '/' + credential_scope + ', ' +  'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature
print ('-- step 4 -- calculate signature and authorization header: \n%s\n' % authorization_header)
# ************* 计算签名 END *************
# 公共参数添加到请求头部
headers = {
              'Authorization': authorization_header,
              'Host': host,
              'Content-Type': 'application/json',
              'X-TC-Action': action,
              'X-TC-Timestamp': str(timestamp),
              'X-TC-Version': version,
              'X-TC-Region': region,
          }
# ************* 发送HTTP请求 *************
print('-- step 5 -- sending request to endpoint: \n{}\nheaders:\n{}\n'.format(endpoint, headers))
r = requests.post(endpoint + canonical_uri + "api3",
                  data=request_parameters,
                  headers=headers)
print('-- step 6 -- receive response: \nstatus code:\n%d\nreponse body: \n%s\n' % (r.status_code, r.text))
