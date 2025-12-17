Project Report: HTTP/1.0 Server and Client Implementation
Brief Description of the Implementation Steps, Framework, and Structure
This project implements a fully functional HTTP/1.0 web server and client from scratch using Python sockets, as per the course requirements for CS/CE 4390.002. The implementation focuses on robustness, thread safety, and custom logic without external HTTP libraries to ensure originality.
Implementation Steps:

Setup and Directories: Created Upload directory for server files and Download for client files. Loaded visitor data from visitors.json on startup.
Server Core: Built a TCP socket listener in the main thread. Parsed requests manually (method, path, version, headers, body) and handled them in worker threads for concurrency.
HTTP Methods: Implemented GET (file retrieval), HEAD (headers only), POST (new file upload), PUT (file update/replace) with path traversal prevention.
Error Handling: Returned 404 for missing files, 403 for permissions/bans, 400 for bad requests.
Multithreading: Used Python's threading module; main thread accepts connections, spawns workers.
Visitor Tracking & Cookies: Thread-safe dictionary for IP-based tracking (count, last time). Set-Cookie headers in responses. Persisted to JSON on shutdown via signal handler.
DoS Protection: Timestamp list per IP, ban if >100 requests/minute (pruned every minute). Ban temporary until restart.
Client: Command-line tool for sending requests, handling responses, file ops, and DoS mode for testing.

Framework and Structure:

server.py: Socket setup, request parsing, method handlers (via dictionary dispatch), tracking, DoS.
client.py: Request builder, file I/O, DoS simulation.
Modular functions for handlers, locks for synchronization. Rate limit: 100 requests/minute.

Precise Outline of How to Run Each File

Server (server.py):
Command: python server.py <port>
Example: python server.py 8080
Listens on specified port, serves files from Upload/. Ctrl+C to shutdown (saves visitors.json).

Client (client.py):
Command: python client.py <serverHost> <serverPort> <filename> <command> [options]
Examples:
GET: python client.py localhost 8080 existing.txt GET (Downloads to Download/).
HEAD: python client.py localhost 8080 existing.txt HEAD (Prints headers).
POST: python client.py localhost 8080 newfile.txt POST (Uploads from Download/).
PUT: python client.py localhost 8080 existing.txt PUT (Updates on server).
DoS: python client.py localhost 8080 test.txt GET -d 200 (Sends 200 rapid GETs).



Various Command Line Options That Have Been Implemented

Server:
<port>: Required port number (e.g., 8080).

Client:
<serverHost>: Hostname/IP (e.g., localhost).
<serverPort>: Port (e.g., 8080).
<filename>: Target file (e.g., test.txt).
<command>: Method (GET/HEAD/POST/PUT).
-d <number>: DoS mode, sends <number> rapid GETs (default 200).