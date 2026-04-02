FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "deb http://http.kali.org/kali kali-rolling main non-free contrib" > /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    nmap \
    nikto \
    sqlmap \
    gobuster \
    ffuf \
    curl \
    wget \
    git \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.1/subfinder_2.6.1_linux_amd64.zip \
    && unzip subfinder_2.6.1_linux_amd64.zip && mv subfinder /usr/local/bin/ && rm subfinder_2.6.1_linux_amd64.zip
WORKDIR /app
RUN pip3 install --no-cache-dir requests anthropic openai
COPY . /app/
RUN mkdir -p /app/output && chmod 777 /app/output
ENTRYPOINT ["python3", "main.py"]
