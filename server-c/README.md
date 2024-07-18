# Simple TCP Server

This C++ program implements a simple TCP server that handles multiple clients using multithreading. The server listens on a specified port (default 8080) and accepts incoming TCP connections. Each client connection is handled in a separate thread.

## Requirements

- GCC (GNU Compiler Collection)
- Linux operating system

## Compilation

To compile the server program, use the following command:

```bash
g++ -o server server.cpp -pthread
```

This command compiles the server source code (server.cpp) into an executable named server. The -pthread flag is used to link the pthread library for multithreading support.

## Running the Server

To run the compiled server program, use:
```bash
./server
```

The server will start and listen on IP address 127.0.0.1 and port 8080 for incoming connections. Modify the source code to change the listening IP address or port as needed.

## Interacting with the Server

Clients can connect to the server using any TCP client (e.g., telnet, nc). Here is an example using telnet:

```bash
telnet 127.0.0.1 8080
```

Type messages and send them to the server. The server will echo received messages back to the terminal. To disconnect, send exit or quit.
