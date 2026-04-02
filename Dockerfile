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
    golang-go \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    mv ~/go/bin/subfinder /usr/local/bin/
WORKDIR /app
RUN pip3 install requests anthropic openai
COPY . .
RUN mkdir -p /app/output && chmod 777 /app/output
ENTRYPOINT ["python3", "main.py"]
