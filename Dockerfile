FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV SCAN_TIMEOUT=3600
ENV VERBOSE=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    sqlmap \
    gobuster \
    ffuf \
    curl \
    wget \
    git \
    unzip \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.1/subfinder_2.6.1_linux_amd64.zip \
    && unzip subfinder_2.6.1_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.1_linux_amd64.zip

RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz \
    && tar -xzf ZAP_2.14.0_Linux.tar.gz \
    && mv ZAP_2.14.0 /opt/zap \
    && ln -s /opt/zap/zap.sh /usr/local/bin/zap.sh \
    && rm ZAP_2.14.0_Linux.tar.gz

RUN mkdir -p /usr/share/wordlists /usr/share/dirb \
    && wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
       -O /usr/share/wordlists/dirb/common.txt \
    && wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
       -O /usr/share/wordlists/subdomains.txt \
    && wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Fuzzing/fuzz.txt \
       -O /usr/share/wordlists/fuzz.txt

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/output

ENV PYTHONPATH=/app
ENV PATH="/app:${PATH}"

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
