import _thread as thread
import time
import base64
import datetime
import hashlib
import hmac
import json
from urllib.parse import urlparse, urlencode
import ssl
from wsgiref.handlers import format_date_time
import websocket


class Ws_Param(object):
    def __init__(self, APPID, APIKey, APISecret, gpt_url):
        self.APPID = APPID
        self.APIKey = APIKey
        self.APISecret = APISecret
        self.host = urlparse(gpt_url).netloc
        self.path = urlparse(gpt_url).path
        self.gpt_url = gpt_url

    def create_url(self):
        now = datetime.datetime.now()
        date = format_date_time(time.mktime(now.timetuple()))

        signature_origin = "host: " + self.host + "\n"
        signature_origin += "date: " + date + "\n"
        signature_origin += "GET " + self.path + " HTTP/1.1"

        signature_sha = hmac.new(self.APISecret.encode('utf-8'), signature_origin.encode('utf-8'),
                                 digestmod=hashlib.sha256).digest()
        signature_sha_base64 = base64.b64encode(signature_sha).decode(encoding='utf-8')

        authorization_origin = f'api_key="{self.APIKey}", algorithm="hmac-sha256", headers="host date request-line", signature="{signature_sha_base64}"'
        authorization = base64.b64encode(authorization_origin.encode('utf-8')).decode(encoding='utf-8')

        v = {
            "authorization": authorization,
            "date": date,
            "host": self.host
        }
        url = self.gpt_url + '?' + urlencode(v)
        return url


def on_error(ws, error):
    print("### error:", error)


def on_close(ws):
    print("### closed ###")


def on_open(ws):
    thread.start_new_thread(run, (ws,))
    ws.start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ws.session_content = []


def run(ws, *args):
    data = json.dumps(gen_params(appid=ws.appid, query=ws.query, domain=ws.domain))
    ws.send(data)


def on_message(ws, message):
    try:
        data = json.loads(message)
        code = data['header']['code']

        if code != 0:
            print(f'请求错误: {code}, {data}')
            ws.close()
        else:
            choices = data["payload"]["choices"]
            status = choices["status"]
            content = choices["text"][0]["content"]

            print(content, end='')

            ws.session_content.append(content)

            if status == 2:
                timestamp = ws.start_time
                log_entry = f"\n\n--- Response received at {timestamp} ---\n{''.join(ws.session_content)}\n"

                with open("response.txt", "a", encoding="utf-8") as file:
                    file.write(log_entry)

                print("#### 关闭会话")
                ws.close()
    except Exception as e:
        print(f"写入文件时出现异常：{e}")


def gen_params(appid, query, domain):
    data = {
        "header": {
            "app_id": appid,
            "uid": "1234",
        },
        "parameter": {
            "chat": {
                "domain": domain,
                "temperature": 0.5,
                "max_tokens": 4096,
                "auditing": "default",
            }
        },
        "payload": {
            "message": {
                "text": [{"role": "user", "content": query}]
            }
        }
    }
    return data


class CustomWebSocketApp(websocket.WebSocketApp):
    def __init__(self, url, *args, **kwargs):
        super().__init__(url, *args, **kwargs)
        self.start_time = None
        self.session_content = []


def main(appid, api_secret, api_key, gpt_url, domain, query):
    wsParam = Ws_Param(appid, api_key, api_secret, gpt_url)
    websocket.enableTrace(False)
    wsUrl = wsParam.create_url()

    ws = CustomWebSocketApp(wsUrl,
                            on_message=on_message,
                            on_error=on_error,
                            on_close=on_close,
                            on_open=on_open)
    ws.appid = appid
    ws.query = query
    ws.domain = domain
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})


if __name__ == "__main__":
    main(
        appid="4a9e5f39",
        api_secret="NTE5Yzk5ODljZTU5ZTllOTczNzEzODUx",
        api_key="f0ab54ae9fa1b44525e662cc8ab96e06",
        gpt_url="wss://spark-api.xf-yun.com/v3.5/chat",
        domain="generalv3.5",
        query="怎么评价王阳明"
    )
