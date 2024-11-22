FROM gradescope/autograder-base:latest as build
RUN apt update && apt install -y libssl-dev
COPY security.c /
RUN gcc -shared -o /libsecurity.so -fPIC /security.c -lcrypto
 
FROM python:alpine
COPY --from=build /libsecurity.so . 
COPY keys/* .
COPY security.py .
COPY roundtrip/start.py .
ENTRYPOINT [ "python", "start.py" ]
