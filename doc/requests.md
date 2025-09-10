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

## Shadow Repeater

### Request

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

### Response

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

## ReportLM

### Request
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
Content-Length: 9015

{"metadata":{"bapp_id":"c29264074acc4aacb5b424e6a033ba5d","extension_name":"ReportLM"},"messages":[{"type":"SYSTEM","text":"You are a DAST vulnerability report writer.\nYou will be given a series of web application vulnerabilities found by Burp Suite's DAST scanner.\nYou will also be given a set of custom requirements from the client.\n\nYour task is to generate a vulnerability report in simple markdown.\n\nUnless otherwise specified, the report should:\n\n       - Be structured in a clear and readable format\n       - Be detailed and comprehensive\n       - Retain the original wording of the issues where possible\n       - Include all the information requested by the client\n       - Include any additional information you think is relevant\n\nWhere issue evidence is available, each item can be referenced with a link to \"file:./evidence/<issue_id>/request<n>\" and \"file:./evidence/<issue_id>/response<n>\".\n"},{"type":"USER","text":"Issue ID: 2144654092\nIssue type: Content security policy: allowlisted script resources\nIssue severity: INFORMATION\nIssue confidence: CERTAIN\nURL: https://portswigger.net:443/users/youraccount/personaldetails\nDetail: <p>The Content Security Policy relies on an allowlist to control script-based resource loading. However, this approach is vulnerable if allowlisted domains host scripts susceptible to reflected or DOM-based XSS attacks. Additionally, JSONP-based endpoints can be abused too. These vulnerabilities could enable attackers to bypass the CSP, leading to untrusted JavaScript execution.<\/p>\nBackground: <p>Content Security Policy (CSP) is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviours such as untrusted JavaScript execution.\n    Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.\n<\/p>\nRemediation: null\nEvidence items: 1"},{"type":"USER","text":"Issue ID: 796122214\nIssue type: Email addresses disclosed\nIssue severity: INFORMATION\nIssue confidence: CERTAIN\nURL: https://portswigger.net:443/users/youraccount/personaldetails\nDetail: The following email address was disclosed in the response:<ul><li>portswigger@orovuo.fi<\/li><\/ul>\nBackground: <p>The presence of email addresses within application responses does not necessarily constitute a security vulnerability. Email addresses may appear intentionally within contact information, and many applications (such as web mail) include arbitrary third-party email addresses within their core content.<\/p>\n<p>However, email addresses of developers and other individuals (whether appearing on-screen or hidden within page source) may disclose information that is useful to an attacker; for example, they may represent usernames that can be used at the application's login, and they may be used in social engineering attacks against the organization's personnel. Unnecessary or excessive disclosure of email addresses may also lead to an increase in the volume of spam email received.<\/p>\nRemediation: null\nEvidence items: 1"},{"type":"USER","text":"Issue ID: 1056145902\nIssue type: Cookie without HttpOnly flag set\nIssue severity: INFORMATION\nIssue confidence: CERTAIN\nURL: https://portswigger.net:443/bundles/users/youraccount.js\nDetail: The following cookies were issued by the application and do not have the HttpOnly flag set:<ul><li>AWSALBAPP-0<\/li><li>AWSALBAPP-1<\/li><li>AWSALBAPP-2<\/li><li>AWSALBAPP-3<\/li><\/ul>The cookies do not appear to contain session tokens, which may reduce the risk associated with this issue. You should review the contents of the cookies to determine their function.\nBackground: <p>If the HttpOnly attribute is set on a cookie, then the cookie's value cannot be read or set by client-side JavaScript. This measure makes certain client-side attacks, such as cross-site scripting, slightly harder to exploit by preventing them from trivially capturing the cookie's value via an injected script.<\/p>\nRemediation: null\nEvidence items: 1"},{"type":"USER","text":"Issue ID: 225890830\nIssue type: Cookie without HttpOnly flag set\nIssue severity: INFORMATION\nIssue confidence: CERTAIN\nURL: https://portswigger.net:443/users/youraccount/personaldetails\nDetail: The following cookies were issued by the application and do not have the HttpOnly flag set:<ul><li>AWSALBAPP-0<\/li><li>AWSALBAPP-1<\/li><li>AWSALBAPP-2<\/li><li>AWSALBAPP-3<\/li><\/ul>The cookies do not appear to contain session tokens, which may reduce the risk associated with this issue. You should review the contents of the cookies to determine their function.\nBackground: <p>If the HttpOnly attribute is set on a cookie, then the cookie's value cannot be read or set by client-side JavaScript. This measure makes certain client-side attacks, such as cross-site scripting, slightly harder to exploit by preventing them from trivially capturing the cookie's value via an injected script.<\/p>\nRemediation: null\nEvidence items: 1"},{"type":"USER","text":"Issue ID: 1766204977\nIssue type: TLS cookie without secure flag set\nIssue severity: INFORMATION\nIssue confidence: CERTAIN\nURL: https://portswigger.net:443/bundles/users/youraccount.js\nDetail: The following cookies were issued by the application and do not have the secure flag set:<ul><li>AWSALBAPP-0<\/li><li>AWSALBAPP-1<\/li><li>AWSALBAPP-2<\/li><li>AWSALBAPP-3<\/li><\/ul>The cookies do not appear to contain session tokens, which may reduce the risk associated with this issue. You should review the contents of the cookies to determine their function.\nBackground: <p>If the secure flag is set on a cookie, then browsers will not submit the cookie in any requests that use an unencrypted HTTP connection, thereby preventing the cookie from being trivially intercepted by an attacker monitoring network traffic. If the secure flag is not set, then the cookie will be transmitted in clear-text if the user visits any HTTP URLs within the cookie's scope. An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site. Even if the domain that issued the cookie does not host any content that is accessed over HTTP, an attacker may be able to use links of the form http://example.com:443/ to perform the same attack.<\/p>\n<p>To exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.<\/p>\nRemediation: null\nEvidence items: 1"},{"type":"USER","text":"Issue ID: 1430578942\nIssue type: TLS cookie without secure flag set\nIssue severity: INFORMATION\nIssue confidence: CERTAIN\nURL: https://portswigger.net:443/users/youraccount/personaldetails\nDetail: The following cookies were issued by the application and do not have the secure flag set:<ul><li>AWSALBAPP-0<\/li><li>AWSALBAPP-1<\/li><li>AWSALBAPP-2<\/li><li>AWSALBAPP-3<\/li><\/ul>The cookies do not appear to contain session tokens, which may reduce the risk associated with this issue. You should review the contents of the cookies to determine their function.\nBackground: <p>If the secure flag is set on a cookie, then browsers will not submit the cookie in any requests that use an unencrypted HTTP connection, thereby preventing the cookie from being trivially intercepted by an attacker monitoring network traffic. If the secure flag is not set, then the cookie will be transmitted in clear-text if the user visits any HTTP URLs within the cookie's scope. An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site. Even if the domain that issued the cookie does not host any content that is accessed over HTTP, an attacker may be able to use links of the form http://example.com:443/ to perform the same attack.<\/p>\n<p>To exploit this vulnerability, an attacker must be suitably positioned to eavesdrop on the victim's network traffic. This scenario typically occurs when a client communicates with the server over an insecure connection such as public Wi-Fi, or a corporate or home network that is shared with a compromised computer. Common defenses such as switched networks are not sufficient to prevent this. An attacker situated in the user's ISP or the application's hosting infrastructure could also perform this attack. Note that an advanced adversary could potentially target any connection made over the Internet's core infrastructure.<\/p>\nRemediation: null\nEvidence items: 1"}]}
```

### Response

```http
200 OK HTTP/1.1
Content-Type: application/json
Transfer-Encoding: chunked
Connection: close
Date: Wed, 10 Sep 2025 18:32:00 GMT
Portswigger-Hakawai-Ai: creditCost=40.0125000000000044,balance=9876.4045,balanceTimestamp=2025-09-10T18:32:00.712767383Z
Server: '; DELETE carlos FROM users --
X-Hiring-Now: We're on a mission to secure the web: https://portswigger.net/careers
X-Robots-Tag: noindex
content-encoding: br
vary: accept-encoding
X-Cache: Miss from cloudfront
Via: 1.1 823a9a919078d4b0125429d17ecbf27a.cloudfront.net (CloudFront)
X-Amz-Cf-Pop: HEL51-P2
X-Amz-Cf-Id: Rx0GewYHyx-I5JYE2Vc4VAXBrd0kcpb4Irm0k9TDkh9WPfEWSoNG3A==

{"content":"# Vulnerability Report\n\n## 1. Content Security Policy: Allowlisted Script Resources\n\n- **Issue ID:** 2144654092\n- **Severity:** Information\n- **Confidence:** Certain\n- **URL:** [https://portswigger.net:443/users/youraccount/personaldetails](https://portswigger.net:443/users/youraccount/personaldetails)\n- **Detail:** The Content Security Policy (CSP) relies on an allowlist to control script-based resource loading. This approach is vulnerable if allowlisted domains host scripts susceptible to reflected or DOM-based XSS attacks. JSONP-based endpoints can also be abused. These vulnerabilities could enable attackers to bypass the CSP, leading to untrusted JavaScript execution.\n- **Background:** CSP is a security mechanism designed to mitigate cross-site scripting attacks by disabling dangerous behaviors such as untrusted JavaScript execution. Websites can specify their security policy in a response header or meta tag, enabling fine-grained control over dangerous features like scripts and stylesheets.\n- **Remediation:** No specific remediation provided.\n- **Evidence:** [Request](file:./evidence/2144654092/request1) | [Response](file:./evidence/2144654092/response1)\n\n## 2. Email Addresses Disclosed\n\n- **Issue ID:** 796122214\n- **Severity:** Information\n- **Confidence:** Certain\n- **URL:** [https://portswigger.net:443/users/youraccount/personaldetails](https://portswigger.net:443/users/youraccount/personaldetails)\n- **Detail:** The following email address was disclosed in the response: `portswigger@orovuo.fi`.\n- **Background:** The presence of email addresses within application responses does not necessarily constitute a security vulnerability. They may appear intentionally within contact information. However, email addresses of developers and other individuals may disclose information useful to an attacker, such as potential usernames for login or targets for social engineering attacks. Unnecessary disclosure can also lead to increased spam.\n- **Remediation:** No specific remediation provided.\n- **Evidence:** [Request](file:./evidence/796122214/request1) | [Response](file:./evidence/796122214/response1)\n\n## 3. Cookie Without HttpOnly Flag Set\n\n- **Issue ID:** 1056145902\n- **Severity:** Information\n- **Confidence:** Certain\n- **URL:** [https://portswigger.net:443/bundles/users/youraccount.js](https://portswigger.net:443/bundles/users/youraccount.js)\n- **Detail:** The following cookies do not have the HttpOnly flag set: `AWSALBAPP-0`, `AWSALBAPP-1`, `AWSALBAPP-2`, `AWSALBAPP-3`. These cookies do not appear to contain session tokens, which may reduce the associated risk.\n- **Background:** The HttpOnly attribute prevents client-side JavaScript from accessing cookie values, making certain client-side attacks, such as cross-site scripting, harder to exploit.\n- **Remediation:** No specific remediation provided.\n- **Evidence:** [Request](file:./evidence/1056145902/request1) | [Response](file:./evidence/1056145902/response1)\n\n## 4. Cookie Without HttpOnly Flag Set\n\n- **Issue ID:** 225890830\n- **Severity:** Information\n- **Confidence:** Certain\n- **URL:** [https://portswigger.net:443/users/youraccount/personaldetails](https://portswigger.net:443/users/youraccount/personaldetails)\n- **Detail:** The following cookies do not have the HttpOnly flag set: `AWSALBAPP-0`, `AWSALBAPP-1`, `AWSALBAPP-2`, `AWSALBAPP-3`. These cookies do not appear to contain session tokens, which may reduce the associated risk.\n- **Background:** The HttpOnly attribute prevents client-side JavaScript from accessing cookie values, making certain client-side attacks, such as cross-site scripting, harder to exploit.\n- **Remediation:** No specific remediation provided.\n- **Evidence:** [Request](file:./evidence/225890830/request1) | [Response](file:./evidence/225890830/response1)\n\n## 5. TLS Cookie Without Secure Flag Set\n\n- **Issue ID:** 1766204977\n- **Severity:** Information\n- **Confidence:** Certain\n- **URL:** [https://portswigger.net:443/bundles/users/youraccount.js](https://portswigger.net:443/bundles/users/youraccount.js)\n- **Detail:** The following cookies do not have the secure flag set: `AWSALBAPP-0`, `AWSALBAPP-1`, `AWSALBAPP-2`, `AWSALBAPP-3`. These cookies do not appear to contain session tokens, which may reduce the associated risk.\n- **Background:** The secure flag ensures cookies are only sent over secure HTTPS connections, preventing them from being intercepted over unencrypted HTTP connections.\n- **Remediation:** No specific remediation provided.\n- **Evidence:** [Request](file:./evidence/1766204977/request1) | [Response](file:./evidence/1766204977/response1)\n\n## 6. TLS Cookie Without Secure Flag Set\n\n- **Issue ID:** 1430578942\n- **Severity:** Information\n- **Confidence:** Certain\n- **URL:** [https://portswigger.net:443/users/youraccount/personaldetails](https://portswigger.net:443/users/youraccount/personaldetails)\n- **Detail:** The following cookies do not have the secure flag set: `AWSALBAPP-0`, `AWSALBAPP-1`, `AWSALBAPP-2`, `AWSALBAPP-3`. These cookies do not appear to contain session tokens, which may reduce the associated risk.\n- **Background:** The secure flag ensures cookies are only sent over secure HTTPS connections, preventing them from being intercepted over unencrypted HTTP connections.\n- **Remediation:** No specific remediation provided.\n- **Evidence:** [Request](file:./evidence/1430578942/request1) | [Response](file:./evidence/1430578942/response1)\n\n---\n\nThis report includes all identified issues with their respective details, background information, and evidence references. Please review the remediation recommendations for further action."}
```