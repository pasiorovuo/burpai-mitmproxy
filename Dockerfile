FROM python:3.14-slim

WORKDIR /app

RUN groupadd mitmproxy && useradd -ms /bin/bash -g mitmproxy mitmproxy

COPY requirements.txt /opt/

RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip3 install --no-cache-dir -r /opt/requirements.txt

ENV PATH="/opt/venv/bin:$PATH"

COPY \
    explore.py \
    prompts.py \
    proxy.py \
    responses.py \
    screenshot.py \
    ./

USER mitmproxy

EXPOSE 9001

CMD exec mitmdump \
    --listen-port 9001 \
    --script proxy.py \
    --set api_key="${CHAT_COMPLETION_API_KEY}" \
    --set model="${CHAT_COMPLETION_MODEL}" \
    --set url="${CHAT_COMPLETION_URL}"
