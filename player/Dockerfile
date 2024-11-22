FROM python:alpine as build1

ENV USER=george
ENV PASSWORD=varghese

RUN mkdir -p /$USER \
    && echo -e "$PASSWORD\n$PASSWORD\n" | adduser --gecos "" --home "/$USER" --no-create-home $USER \
    && mkdir -p /$USER/.ssh \
    && chmod 0700 /$USER/.ssh \
    && apk add openrc openssh \
    && ssh-keygen -A \
    && mkdir -p /run/openrc \
    && touch /run/openrc/softlevel \
    && echo -e "How exciting! Someone found my server! Good luck..." > /etc/motd \
    && apk add --update bind-tools \
    && apk add build-base

COPY player/repl.py /$USER
COPY player/socket /$USER
COPY security.py /$USER

FROM gradescope/autograder-base:latest as build2
RUN apt update && apt install -y libssl-dev
COPY security.c /
RUN gcc -shared -o /libsecurity.so -fPIC /security.c -lcrypto

FROM build1
COPY --from=build2 /libsecurity.so /$USER
CMD ["sh", "-c", "rc-status; rc-service sshd start; cat"]
