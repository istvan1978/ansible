#!/bin/bash

# yum -- absent
sudo yum remove docker \
                docker-client \
                docker-client-latest \
                docker-common \
                docker-latest \
                docker-latest-logrotate \
                docker-logrotate \
                docker-engine

# yum -- latest
sudo yum install -y yum-utils

# shell 
sudo yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo

# yum -- latest
sudo yum install docker-ce docker-ce-cli containerd.io

# service -- started / enabled
sudo systemctl start docker
