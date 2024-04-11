# mystery
A scavenger hunt mystery for CS 118

## Requirements
Docker >=v24  
Ports open:
- 80 (Public progress dashboard)
- 22[0-n] (where n is the number of players)

## Setup
Run `start.bash`. To change the number of players (default 10, max 100), 
add the option `-n <num>` where `<num>` is the number of players you want to
instantiate.

This will:
- Create n + 1 Docker containers with the name `player<i>`.
  - This includes `player0` for demonstration.
  - Each will have ssh open on port `22<i:2>` (for example, `player1` has port
    `2201` open).
  - These are inflitration servers that players use as a starting point.
- Create 3 target server Docker containers. These are servers that players try
  to access. 
  - `clk`: basics of connecting
  - `rfc`: finding the path
  - `roundtrip`: serving for the first time
- Create a progress server to track players' inflitration. 
  - Each target sends a message to the progress server whenever they're accessed
    by a certain IP. 
  - It's also open on port 80 to show a website with progress bars for each
    player.