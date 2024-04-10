# mystery
A scavenger hunt mystery for CS 118

## Requirements
Docker >=v24
Ports open:
- 80 (Public progress dashboard)
- 22[0-n] (where n is the number of players)

## Setup
Run `start.sh`. To change the number of players (default 10), add the option `-n <num>` where `<num>` is the number of players you want to instantiate. 

This will:
- Create n + 1 Docker containers with the name `player<i>`.
  - This includes `player0` for demonstration.
  - Each will have ssh open on port `22<i:2>` (for example, `player1` has port `2201` open).
