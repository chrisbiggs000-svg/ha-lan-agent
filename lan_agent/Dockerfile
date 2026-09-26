ARG BUILD_ARCH=aarch64
FROM ghcr.io/home-assistant/${BUILD_ARCH}-base-python:3.13-alpine3.23

# Ensure pip is available (base image already has python3)
RUN apk add --no-cache py3-pip

WORKDIR /app
COPY agent.py protocol.py requirements.txt ./
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY run.sh /
RUN chmod +x /run.sh

CMD ["/run.sh"]
