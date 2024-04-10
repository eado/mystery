FROM alpine:3.19

ENV USER=gene
ENV PASSWORD=block

RUN mkdir -p /$USER \
    && echo -e "$PASSWORD\n$PASSWORD\n" | adduser --gecos "" --home "/$USER" --no-create-home $USER \
    && mkdir -p /$USER/.ssh \
    && chmod 0700 /$USER/.ssh \
    && apk add openrc openssh \
    && ssh-keygen -A \
    && mkdir -p /run/openrc \
    && touch /run/openrc/softlevel \
    && echo -e "How exciting! Someone found my server! Good luck..." > /etc/motd \
    && apk add --update bind-tools

COPY socket /$USER
COPY socket.c /$USER

ENTRYPOINT ["sh", "-c", "rc-status; rc-service sshd start; cat"]

