# Honey I'm Home

Track nearby devices based on WiFi beacons, using MAC addresses!

### Usage examples

| Command                                               | Result                                                          |
| ----------------------------------------------------- | --------------------------------------------------------------- |
| `python3 main.py scan -i wlp3s0`                      | Scans for clients nearby and prints their MAC and SSID          |
| `python3 main.py scan -i wlp3s0 -s johndoe`           | Scans for clients with SSID matching `johndoe`                  |
| `python3 main.py scan -i wlp3s0 -m 00:00:00:00:00:00` | Scans for clients with MAC address matching `00:00:00:00:00:00` |


### To do

 - [ ] Implement database support
    - [x] sqlite3 DB initialization (the code is commented but there)
    - [ ] Add `--database` argument to use instead of `-m` or `-s`
      - [ ] Implement loading clients from database
        - [ ] Figure out how to pass multiple MAC+SSID pairs to `scan_clients()` (for database support)
    - [ ] Rewrite "add" subcommand to "db"
      - [ ] `./main.py db --add name,mac` to add a new client
      - [ ] `./main.py db --show` to list saved clients
      - [ ] `./main.py db --delete name` to delete a client
