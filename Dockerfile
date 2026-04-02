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
    && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/OJ/gobuster/releases/download/v3.6/gobuster_3.6_linux_amd64.tar.gz && \
    tar -xzf gobuster_3.6_linux_amd64.tar.gz && \
    mv gobuster /usr/local/bin/ && \
    rm gobuster_3.6_linux_amd64.tar.gz
RUN wget -q https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    tar -xzf ffuf_2.1.0_linux_amd64.tar.gz && \
    mv ffuf /usr/local/bin/ && \
    rm ffuf_2.1.0_linux_amd64.tar.gz
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    unzip subfinder_2.6.6_linux_amd64.zip && \
    mv subfinder /usr/local/bin/ && \
    rm subfinder_2.6.6_linux_amd64.zip
WORKDIR /app
COPY requirements.txt .
RUN pip3 install requests anthropic openai
COPY . .
RUN mkdir -p /app/output
CMD ["python3", "main.py"]
