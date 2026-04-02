FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONPATH=/app

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
    || true

RUN echo "Installing gobuster..." && \
    (wget -q https://github.com/OJ/gobuster/releases/download/v3.5/gobuster_3.5_linux_amd64.tar.gz -O /tmp/gobuster.tar.gz && tar -xzf /tmp/gobuster.tar.gz -C /tmp && mv /tmp/gobuster /usr/local/bin/gobuster && rm /tmp/gobuster.tar.gz) || \
    (apt-get install -y gobuster || true) || \
    echo "GOBUSTER SKIPPED - continuing..."

RUN echo "Installing ffuf..." && \
    (wget -q https://github.com/ffuf/ffuf/releases/download/v2.0.0/ffuf_2.0.0_linux_amd64.tar.gz -O /tmp/ffuf.tar.gz && tar -xzf /tmp/ffuf.tar.gz -C /tmp && mv /tmp/ffuf /usr/local/bin/ffuf && rm /tmp/ffuf.tar.gz) || \
    echo "FFUF SKIPPED - continuing..."

RUN echo "Installing subfinder..." && \
    (apt-get install -y golang-go || true) && \
    (curl -sL https://go.dev/dl/go1.21.6.linux-amd64.tar.gz | tar -C /usr/local -xzf - && export PATH=$PATH:/usr/local/go/bin && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null && cp ~/go/bin/subfinder /usr/local/bin/ 2>/dev/null || cp /root/go/bin/subfinder /usr/local/bin/ 2>/dev/null || true) || \
    echo "SUBFINDER SKIPPED - continuing..."

WORKDIR /app

RUN pip3 install --break-system-packages requests anthropic openai || pip3 install requests anthropic openai

COPY . .

RUN mkdir -p /app/output && chmod 777 /app/output

CMD ["python3", "-u", "main.py"]
