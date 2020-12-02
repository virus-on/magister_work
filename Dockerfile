FROM ubuntu:latest

RUN apt-get update -y
RUN apt-get install -y python3-pip python3-dev build-essential nmap git
RUN git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/vulners
RUN nmap --script-updatedb
COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
ENTRYPOINT ["python3", "-u", "telegramBot.py"]
