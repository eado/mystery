#!/bin/bash

# Get number of players
n=10

if [ $# -eq 1 ]; then
    n=$1
elif [ $# -gt 1 ]; then
    echo "Usage: $0 [n]"
    echo "Where n is the optional number of player containers to start. Default is 10. Max is 100."
    exit 1
fi

# Remove everything
docker stop `docker ps -qa`
docker rm `docker ps -qa`
docker network rm `docker network ls -q`

# Setup listening builds
sed -i '' "s/^NUMSERVERS = .*/NUMSERVERS = $n/" roundtrip/start.py

# Build images
docker build -t player -f player/Dockerfile .
docker build -t roundtrip -f roundtrip/Dockerfile .
docker build -t progress progress

# Create network
docker network create --subnet 10.0.0.0/16 iso

# Run players
for i in $(seq 0 $n); do
    suffix=$(printf "%02d" $i)
    docker run -h "player$i" --name "player$i" --net iso --ip "10.0.0.1$suffix" -p "22$suffix:22" -td player
done

# Run servers
docker run -h roundtrip --name roundtrip --net iso --ip 10.0.213.12 -td roundtrip
docker run -h progress --name progress --net iso --ip 10.0.0.2 -p "80:8080" -td progress

