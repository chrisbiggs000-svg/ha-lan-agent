ARG BUILD_FROM
FROM $BUILD_FROM

# Install Python and dependencies
RUN apk add --no-cache python3 py3-pip

WORKDIR /app
COPY agent.py requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

COPY run.sh /
RUN chmod +x /run.sh

CMD ["/run.sh"]
