# P4 Project - File Transfer Server

## Overview
This project implements a a client/server networked application that allows clients to store and load files under specific paths. The server can handle multiple clients simultaneously and supports various file operations such as checking the existence of a file, loading a file's contents, storing data into a file, and deleting a file.

## Features
- **Server Mode**: Listens for incoming client connections and handles file management commands.
- **Client Mode**: Connects to the server to execute file management commands.
- **Commands**:
  - `check`: Check if a file exists on the server.
  - `load`: Load and display the contents of a file from the server.
  - `store`: Store user-provided data into a file on the server.
  - `delete`: Delete a file on the server.

## Dependencies
- Standard C++ libraries: `<iostream>`, `<cstdint>`, `<cstring>`, `<stdexcept>`, `<fstream>`, `<sstream>`, `<thread>`, `<mutex>`, `<atomic>`, `<csignal>`
- *NIX headers: `<unistd.h>`, `<sys/socket.h>`, `<arpa/inet.h>`, `<sys/stat.h>`

## Compilation
Use the following command to compile the project:
```sh
g++ -o p4 p4.cpp -pthread
