# Explain this (/ai/hakawai-explain-this/api/v1/explainthis)

Executed when a portion of the request/response is selected (in Repeater) and "Explain this" is selected.
Known contexts:

- REQUEST_LINE
- REQUEST_HEADERS
- REQUEST_BODY
- REQUEST
- RESPONSE_STATUS_LINE
- RESPONSE_HEADERS
- RESPONSE_BODY
- RESPONSE

## Request
```http
POST https://ai.portswigger.net/ai/hakawai-explain-this/api/v1/explainthis HTTP/1.1
Host: ai.portswigger.net
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="139", "Not=A?Brand";v="8", "Chromium";v="139"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: close
Portswigger-Burp-Ai-Token: ...
Content-Type: application/json; charset=utf-8
Content-Length: 95

{"text":"\/users/youraccount/personaldetails?admin='+select(453)+--+","context":"REQUEST_LINE"}
```

## Response
```http
200 OK HTTP/1.1
Content-Type: application/json
Content-Length: 442
Connection: close
Portswigger-Hakawai-Ai: creditCost=4.923,balance=9986.189,balanceTimestamp=2025-09-08T09:23:29.572802002Z
Server: '; DELETE carlos FROM users --
X-Hiring-Now: We're on a mission to secure the web: https://portswigger.net/careers
X-Robots-Tag: noindex
Date: Mon, 08 Sep 2025 09:23:29 GMT
X-Cache: Miss from cloudfront
Via: 1.1 bbb264dfd2d5430ae34f8bc6e1432b46.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: HEL51-P2
X-Amz-Cf-Id: 7vaeHXbPfS2afn62tuLYgxF6zcv8uQeNSnlJuwZYOhnObdazZ2lvIg==

{"content":"This is a URL from an HTTP request line that seems to be attempting a SQL injection attack. The URL includes an SQL command injection attempt with the `'+select(453)+--+` portion, which tries to manipulate the query executed by the server. The `--` serves as a comment indicator in SQL, potentially truncating any remaining part of the SQL statement. It's a good example of malicious input that could target a vulnerable system."}
```

# Extension Prompt

## Request

```http
POST https://ai.portswigger.net/ai/hakawai-montoya-service/api/v1/prompt HTTP/1.1
Host: ai.portswigger.net
Cache-Control: max-age=0
Sec-Ch-Ua: "Google Chrome";v="139", "Not=A?Brand";v="8", "Chromium";v="139"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Connection: close
Portswigger-Burp-Ai-Token: ...
Content-Type: application/json; charset=utf-8
Content-Length: 1407

{"metadata":{"bapp_id":"7be1798d600647688bb2f051da37f504","extension_name":"Shadow Repeater"},"config":{"temperature":"1.0"},"messages":[{"type":"SYSTEM","text":"You are a web security expert.\nYour job is to analyze the JSON given to you and look for variations of what's being tested.\nYou should return list of 10 vectors separated by new lines.Return **only vectors separated by new lines**. No markdown, no code blocks, and no extra text.\nDo not output markdown.\nDo not describe anything. Do not explain anything.\nYou should be creative when coming up with your variations.\nYou should avoid making up and spoofing domains.\nCheck for any patterns that align with RFC specifications.\nIf an RFC pattern is detected, focus the analysis on its compliance with the specification when producing variations.\nDo not use example domains, you should always use the existing domains in the data your analyzing.\nWhat are the structural differences between the vectors in this dataset?\n- Identify other possible variations that could follow the same pattern.\n- Extract common patterns from this data and generate equivalent vectors used in other contexts.\nHere is a list of headers and parameters for you to analyse in JSON:\n"},{"type":"USER","text":"[{\"name\":\"admin\",\"type\":\"URL\",\"value\":\"'+select+version()+--+\"},{\"name\":\"admin\",\"type\":\"URL\",\"value\":\"'+select+version+--+\"}]"}]}
```

## Response

```http
200 OK HTTP/1.1
Content-Type: application/json
Content-Length: 338
Connection: close
Portswigger-Hakawai-Ai: creditCost=4.1415,balance=9920.3275,balanceTimestamp=2025-09-09T11:51:49.161028028Z
Server: '; DELETE carlos FROM users --
X-Hiring-Now: We're on a mission to secure the web: https://portswigger.net/careers
X-Robots-Tag: noindex
Date: Tue, 09 Sep 2025 11:51:49 GMT
X-Cache: Miss from cloudfront
Via: 1.1 63da0bbf8b25d5b1660d6c41698bd6bc.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: HEL51-P2
X-Amz-Cf-Id: 67OIdOokleOnOdLswazq79_qq2fjWJh9le0v4wNHDZaUAD6Y0nTeUA==

{"content":"'+select+user()+--+  \n'+union+select+null--+  \n'+union+select+1,2,3--+  \n'+extractvalue(null,concat(0x3a,version()))--+  \n'+floor(rand(0)*2)--+  \n' and 1=0 union select '+user()+--+  \n' or 1=1 order by 1--+  \n' and ascii(substring((@@version),1,1))=52--+  \n' and benchmark(1000000,md5(1))--+'  \n' or pg_sleep(5)--+'"}
```
