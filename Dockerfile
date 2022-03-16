FROM ubuntu:latest
ENV DEBIAN_FRONTEND="noninteractive"
ENV TZ="Asia/Kolkata"
WORKDIR /app
RUN apt update 
RUN apt upgrade -y
RUN apt install python wget -y
COPY requirements.txt .
RUN apt install python3-pip -y
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
RUN python2 get-pip.py
RUN python2 -m pip install colorama requests
#RUN apt-get update; apt-get install make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev -y
CMD ["bash","startup"]
