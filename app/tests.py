import urllib
import hashlib
import random
import requests
import time


# auto自动识别语言,中文：zh
def translateBaidu(content, fromLang='auto', toLang='zh'):
    apiurl = 'http://api.fanyi.baidu.com/api/trans/vip/translate'
    appid = '20221008001375921'
    secretyKey = 'Nln1Fy8HMpLl5gxioV9_'
    salt = str(random.randint(32768, 65536))
    sign = appid + content + salt + secretyKey
    sign = hashlib.md5(sign.encode('utf-8')).hexdigest()
    apiurl = apiurl + '?appid=' + appid + '&q=' + urllib.parse.quote(
        content) + '&from=' + fromLang + '&to=' + toLang + '&salt=' + salt + '&sign=' + sign
    try:
        time.sleep(1.5)
        res = requests.get(apiurl)
        json_res = res.json()
        dst = str(json_res['trans_result'][0]['dst'])
        return dst
    except Exception as e:
        print('翻译失败：', e)
        return '翻译失败：' + content


if __name__ == "__main__":
    content = 'Hating people is like burning down your own house to get rid of a rat.'
    res = translateBaidu(content)
    print('翻译结果：\n', res)
