# Video Game Rental System with TLS Security
# By: Hadam Dicko

## Overview
This is a secure implementation of a video game rental system that uses TLS 1.3 for encrypted communication between clients and the server. The system includes user authentication, password management, and various game rental features.

## Features
- TLS 1.3 encrypted communication
- Secure user authentication system
- PBKDF2-HMAC-SHA256 password hashing with salting
- Case-insensitive commands for better user experience
- Browse, rent, and manage games
- Concurrent client support

## Requirements
- C++20 capable compiler
- OpenSSL 3.2.2+ library
- POSIX-compliant operating system (Linux, macOS)

## Files
- `server.cpp` - Main server implementation with TLS and authentication
- `p1_helper.h` - Helper functions and structures
- `p1_helper.cpp` - Implementation of helper functions
- `server.conf` - Server configuration file (port settings)
- `games.db` - Database of available games
- `Makefile` - Build instructions

## Building
To build the server:

```bash
make
```
This will compile both the server and client applications using the Makefile provided.

## Self-Signed Cert Generation 
Before running the server, you need to generate self-signed certificates:
```bash
openssl req -x509 -newkey rsa:2048 -keyout p3server.key -out p3server.crt -days 365 -nodes
```
When prompted, use "localhost" as the Common Name if testing locally.

## Running the Server
```bash
/server server.conf
```
The server will read the port number from the configuration file and start listening for incoming connections.

## Connecting to the Server
To connect to the server, use the OpenSSL s_client tool with TLS 1.3:
```bash
openssl s_client -quiet -connect localhost:12345 -tls1_3
```
The -quiet flag is important for proper command functionality, particularly for the RENT and CHECKOUT commands.

## User Authentication 
New users will be automatically registered with a system-generated secure password:
```bash
USER username
```
For existing users, you'll be prompted for a password:
```bash
USER username
PASS your_password
```

## Commands
After authentication, the following commands are available:

General Commands 
```bash
HELP - Display available commands
BROWSE - Switch to browse mode
RENT - Switch to rent mode
MYGAMES - Switch to my games mode
BYE - Terminate the connection
```
BROWSE MODE
```bash
LIST [filter] - List all games or filter by title, genre, platform, or rating
SEARCH <filter> <keyword> - Search games by filter and keyword
SHOW <game_id> [availability] - Show details for a specific game
```

Rent Mode
```bash
CHECKOUT <game_id> - Rent a game
RETURN <game_id> - Return a previously rented game
```

MyGames Mode
```bash
HISTORY - View your rental history
RECOMMEND [filter] - Get game recommendations based on your rentals
RATE <game_id> <rating> - Rate a game from 1-10
```

## Response Codes
The server uses a numerical response code system to communicate status:
Success Codes (2xx)
```bash
200 - Generic success, OK
210 - Authentication successful / Switched to Browse Mode
220 - Switched to Rent Mode
230 - Switched to Mygames Mode
250 - Operation successful with data following
```
Intermediate Codes (3xx)
```bash
300 - Password required (after USER command)
304 - No content available (empty results)
```
Error Codes (4xx)
```bash
400 - Bad request (invalid command or parameters)
401 - Authentication required
403 - Forbidden (e.g., trying to rent unavailable game)
404 - Not found (game, user, etc.)
410 - Authentication failed
```
Server Error Codes (5xx)
```bash
503 - Bad sequence of commands (mode-specific command used in wrong mode)
```

## Known Issues
OpenSSL s_client may experience disconnection issues when switching modes. Use the -quiet flag to mitigate these issues.

Authentication system may require manual deletion of .games_shadow file between testing sessions.
