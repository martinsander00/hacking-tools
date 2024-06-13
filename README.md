# Server.s Documentation

## Overview
`server.s` is an assembly program designed to handle HTTP requests. It processes both POST and GET requests, responding based on the request type.

## Features
- **POST Request Handling:** Processes incoming POST requests by parsing the data received and executing defined actions.
- **GET Request Handling:** Retrieves and sends data in response to GET requests according to the query parameters.

## Assembly Directives
- `.as` directive is used for assembling the server logic.
- `.link` directive manages linking external modules or libraries necessary for request processing.

## Usage
To run `server.s`, ensure you have the appropriate assembly environment set up and use the following commands:
```bash
as -o server.o server.s   # Assemble the code
ld -o server server.o     # Link the object file to create an executable
./server                  # Run the server

