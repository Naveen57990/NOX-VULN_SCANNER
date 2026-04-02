FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    wget \
    curl \
    git \
    unzip \
    default-jre-headless \
    nmap \
    nikto \
    sqlmap \
    ruby \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sL https://github.com/ffuf/ffuf/releases/download/v2.0.0/ffuf_2.0.0_linux_amd64.tar.gz -o /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp && \
    mv /tmp/ffuf /usr/local/bin/ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm /tmp/ffuf.tar.gz

RUN curl -sL https://github.com/OJ/gobuster/releases/download/v3.5/gobuster_3.5_linux_amd64.tar.gz -o /tmp/gobuster.tar.gz && \
    tar -xzf /tmp/gobuster.tar.gz -C /tmp && \
    mv /tmp/gobuster /usr/local/bin/gobuster && \
    chmod +x /usr/local/bin/gobuster && \
    rm /tmp/gobuster.tar.gz

RUN curl -sL https://go.dev/dl/go1.21.6.linux-amd64.tar.gz | tar -C /usr/local -xzf - && \
    export PATH=$PATH:/usr/local/go/bin:/root/go/bin && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    cp /root/go/bin/subfinder /usr/local/bin/subfinder || true

WORKDIR /app

RUN pip3 install --break-system-packages requests anthropic openai

COPY . .

RUN mkdir -p /app/output && chmod 777 /app/output

CMD ["python3", "main.py"]
