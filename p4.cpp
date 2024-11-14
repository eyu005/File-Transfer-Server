//Eunsang Yu
//05/31/2024
//CPSC 3500
//P4

#include <iostream>
#include <cstdint>
#include <libgen.h>
// Standard *NIX headers
#include <unistd.h>
// Socket functionality
#include <sys/socket.h>
// TCP/IP protocol functionaltiy
#include <arpa/inet.h>
#include <cstring>
#include <sys/stat.h>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <signal.h>
#include <csignal>
#include <condition_variable>

std::atomic<bool> stop_flag(false);
std::mutex stop_mutex;
std::condition_variable stop_cv;

void signal_handler(int signal);
void client(in_addr_t ip, in_port_t port);

// Servers pick an arbitrary port number and reports its port
// number to the user
void server();

// Functions for parsing ip addresses and port numbers from
// c strings
in_addr_t parse_ip(char*   ip_str);
in_port_t parse_port(char* port_str);

// Returns a socket file descriptor that is connected to the
// given ip/port
int connect_to(in_addr_t ip, in_port_t port);
// Returns a socket bound to an arbitrary port
int arbitrary_socket();
// Returns the port of the socket referenced by the input file descriptor
in_port_t get_port(int socket_fd);

void send_error_response(int connection_fd);
void send_response(int connection_fd, uint32_t response_code);


// Functions that can send/recv exactly N bytes of information from/into a buffer.
void send_n(int socket, const void *buffer, size_t n, int flags) ;
void recv_n(int socket, void *buffer, size_t n, int flags);

// Functions that can send/recv a std::string. 
void send_string(int sockfd, const std::string& str);
std::string recv_string(int sockfd);

// Functions for checking if a file exists at path <path> relative to the server at 
// <ip> <port>
void command_check(in_addr_t ip, in_port_t port, std::string& path);
void handle_check_command(int connection_fd);

// Functions for printing the conetent of the file at path <path> relative to the server at 
// <ip> <port>
void command_load(in_addr_t ip, in_port_t port, std::string& path);
void handle_load_command(int connecton_fd);

// Functions for wrting input to the file at path <path> relative to the serverr at 
// <ip> <port>.
void command_store(in_addr_t ip, in_port_t port, std::string& path);
void handle_store_command(int connection_fd);

// Functions for deleting a file at path <path> relative to the server at 
// <ip> <port>
void command_delete(in_addr_t ip, in_port_t port, std::string& path);
void handle_delete_command(int connection_fd);

// Function handles client requests.
void handle_client(int connection_fd);

int main(int argc, char *argv[]) {
try {
        if(argc < 2){
            std::cout << "Usage: p4 [mode] [options ...]" << std::endl;
            return 1;
        }

        std::string mode = argv[1];
        if (mode == "server"){
            if(argc != 2){
                std::cout << "Usage: p4 server" << std::endl;
                return 1;
            }
            server();
        } else {
            if (argc < 5) {
                std::cout << "Usage: p4 " << mode << " <ip> <port> <path>" << std::endl;
                return 1;
            }
            std::string path = argv[4];
            in_addr_t ip = parse_ip(argv[2]);
            in_port_t port = parse_port(argv[3]);

            if (mode == "check") {
                command_check(ip, port, path);
            } else if (mode == "load") {
                command_load(ip, port, path);
            } else if (mode == "store") {
                command_store(ip, port, path);
            } else if (mode == "delete") {
                command_delete(ip, port, path);
            } else {
                std::cout << "Mode '" << mode << "' not recognized" << std::endl;
                return 1;
            }
            
            path.clear();
            path.shrink_to_fit();
        }

        mode.clear();
        mode.shrink_to_fit();

        return 0;
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}

// Desc: Sends exact number of N bytes from buffer over a socket. 
// Pre-condition: sockfd must be valid, buffer must point to a valid memory location, 
// n must be non-negative value, flags must be valid.
// Post-condition: Exactly n bytes from the buffer have been sent over. 
// total_sent variable equals n after the loop completes. 
void send_n(int sockfd, const void *buffer, size_t n, int flags) {
    size_t total_sent = 0;
    const char *data = static_cast<const char*>(buffer);
    
    while (total_sent < n) {
        ssize_t sent = send(sockfd, data + total_sent, n - total_sent, 0);
        if (sent == -1) {
            throw std::runtime_error("Socket send error: " + std::string(strerror(errno)));        
        }
        if (sent == 0) {
            throw std::runtime_error("Socket connection closed while sending");
        }
        total_sent += sent;
    }
}

// Desc: It receives exactly n bytes into a buffer from a socket. 
// Pre-condition: sockfd must be valid, buffer must point to a valid memory location, 
// n must be non-negative value, flags must be valid.
// post-condition: Exactly n bytes have been received and stored in the buffer.
// total_received must equal n bytes after the loop completes. 
void recv_n(int sockfd, void *buffer, size_t n, int flags) {
    size_t total_received = 0;
    char* data = static_cast<char*>(buffer);

    while (total_received < n) {
        ssize_t received = recv(sockfd, data + total_received, n - total_received, 0);
        if(received == -1) {
            std::cout << "Socket receive error: " << std::string(strerror(errno));       
        }
        if(received == 0) {
            std::cout << "Socket connection closed while receiving" << std::endl;
        }
        total_received += received;
    }
}

// Desc: Sends the length of the string as a 32-bit unsigned integer in network byte order, 
// followed by the string data itself.
// Pre-condition: The sockfd and str parameter must be valid.
// Post-condition: Length of the string has been sent over the socket. 
// The string data has been sent over the socket
void send_string(int sockfd, const std::string& str) {
    uint32_t len = htonl(str.size());
    send_n(sockfd, &len, sizeof(len), 0);      // Send the length of the string 
    send_n(sockfd, str.data(), str.size(), 0); // Sent he string data 
}

// Desc: Receives the length of the string as a 32-bit unsigned integer in network byte order, 
// converts it to host byte order, receives the string data based on the length. 
// Pre-condition: The sockfd parameter must be valid.
// Post-condition: Length of the string has been received and converted to host byte order.
// The string data has been received over the socket
std::string recv_string(int sockfd) {
    uint32_t len;
    recv_n(sockfd, &len, sizeof(len), 0);
    len = ntohl(len);

    std::string str;
    if (len > 0) {
        str.resize(len);
        recv_n(sockfd, &str[0], len, 0);
    }

    return str; 
}

// desc : Parses a string to an ip address
// pre  : ip_str points to a valid c_string
// post : Returns the parsed ip or throws a runtime error
in_addr_t parse_ip(char*   ip_str) {
    // The 'in_addr_t' type represents an ip address, and can be
    // parsed from a string using 'inet_addr'
    in_addr_t ip_addr = inet_addr(ip_str);
    // If the parsing failed, the INADDR_NONE value will be produced
    if (ip_addr == INADDR_NONE) {
        throw std::runtime_error("Failed to convert input ip address.");     
    }
    return ip_addr;
}

// desc : Parses a string to a port number
// pre  : port_str points to a valid c_string
// post : Returns the parsed port number or throws a runtime exception
in_port_t parse_port(char* port_str) {
    // Parse port number from argument
    in_port_t port = atoi(port_str);
    // 'atoi' returns zero on error. Port zero is not a 'real' port.
    if(port == 0) {
        throw std::runtime_error("Invalid port argument.");     
    }
    return port;
}

// desc : Returns a tcp/ip socket
// pre  : None
// post : Returns a tcp/ip socket or throws a runtime exception
int make_tcp_ip_socket() {
    // Make a socket, which is a special type of file that acts as a
    // holding area for sent/recieved data.
    //
    //  - PF_INET means the Port Family is for InterNET
    //  - SOCK_STREAM indicates it should use the TCP protocol
    int socket_fd = socket(PF_INET,SOCK_STREAM,0);
    // If the fd is negative, socket allocation failed
    if(socket_fd < 0){
        throw std::runtime_error("Could not allocate socket.");
    }
    return socket_fd;
}


// desc : Returns a socket connected to the given ip address and
//        port number
// pre  : ip is a valid ip address. port is a valid port number
// post : If an error is encountered, a runtime exception is thrown
int connect_to(in_addr_t ip, in_port_t port) {
    // Set up socket address data structure, which we will use
    // to tell the OS what we want to do with our socket
    sockaddr_in socket_addr;
    // AF_INET means the Address Family is for InterNET
    socket_addr.sin_family = AF_INET;
    // Set the ip address to connect to
    socket_addr.sin_addr.s_addr = ip;
    // Set the port to connect to
    // htons converts endianness from host to network
    socket_addr.sin_port = htons(port);

    // Make socket to connect through
    int socket_fd = make_tcp_ip_socket();

    // Tell the OS we want to connect to the ip/port indicated by
    // socket_addr through the socket represented by the file
    // descriptor 'socket_fd'
    int status = connect(socket_fd,(sockaddr*)&socket_addr,sizeof(socket_addr));
    // If output is negative, the connection was not successful.
    if(status < 0) {
        // Make sure socket get cleaned up
        close(socket_fd);
        throw std::runtime_error("Connection failed.");
    }
    return socket_fd;
}

// desc : Returns a socket bound to an arbitrary port
// pre  : None
// post : If an error is returned, a runtime exception is thrown
int arbitrary_socket() {
    // Set up socket address data structure, which we will use
    // to tell the OS what we want to do with our socket
    sockaddr_in socket_addr;
    // AF_INET means the Address Family is for InterNET
    socket_addr.sin_family = AF_INET;
    // Indicate we are willing to connect with any ip address
    socket_addr.sin_addr.s_addr = INADDR_ANY;
    // Use zero-valued port to tell OS to pick any available
    // port number
    socket_addr.sin_port = 0;

    // Make a socket to listen through
    int socket_fd = make_tcp_ip_socket();

    // Bind socket to an arbitrary available port
    int status = bind(
        socket_fd,
        (struct sockaddr *) &socket_addr,
        sizeof(sockaddr_in)
    );
    if(status < 0) {
        throw std::runtime_error("Binding failed.");
    }
    return socket_fd;
}

// desc : Returns the port that the provided file descriptor's
//        socket is bound to
// pre  : The provided socket file descriptor is valid
// post : If an error is encountered, a runtime exception is thrown
in_port_t get_port(int socket_fd) {
    // A receptacle for the syscall to write the port number
    sockaddr_in socket_addr;
    // You need to supply the size of the receptacle through
    // a pointer. This seems rather silly, but is onetheless necessary.
    socklen_t socklen = sizeof(sockaddr_in);
    // Get the "name" (aka port number) of socket
    int status = getsockname(
        socket_fd,
        (struct sockaddr *) &socket_addr,
        &socklen
    );
    if (status < 0) {
        throw std::runtime_error("Failed to find socket's port number.");
    }
    // Flip endianness from network to host
    return ntohs(socket_addr.sin_port);
}

//Desc: Sends a predefined error response over a socket
//Pre: Must be a valid, conected socket
//Post: The error response code has been sent over the socket
void send_error_response(int connection_fd) {
    uint32_t response = htonl(1);
    send_n(connection_fd, &response, sizeof(response), 0);
}

//Desc: Sends a specified response code over a socket. 
//Pre: Must be a valid, connected socket
//Post: The specified response code has been sent over the socket.
void send_response(int connection_fd, uint32_t response_code) {
    uint32_t response = htonl(response_code);
    send_n(connection_fd, &response, sizeof(response), 0);
}

//Desc: Connects to a specified server, sends a command to chekc for the existence of a file
//at a given path, and handles the server's response. If the file exists, the function exits with status 
//code 0. If not, exits with status code 1. 
//Pre: ip parameter must be valid, port prameter must be valid port number, path must be a valid string
//Post: A command has been sent to the server. The specified file path has been sent to the server. 
//A response from the server has been received and interpreted. 
void command_check(in_addr_t ip, in_port_t port, std::string& path) {
    int socket_fd = connect_to(ip, port);
    if (socket_fd < 0) {
        std::cout << "Failed to connect to server" << std::endl;
        exit(1);
    }
    try {
        uint32_t command = htonl(1);
        send_n(socket_fd, reinterpret_cast<const void*>(&command), sizeof(command), 0);
        std::cout << "Sending path to server: " << path << std::endl;
        send_string(socket_fd, path);

        uint32_t response;
        recv_n(socket_fd, reinterpret_cast<void*>(&response), sizeof(response), 0);
        response = ntohl(response);

        if (response == 0) {
            std::cout << "File exists" << std::endl;
            path.clear(); // Clear the string to release memory
            path.shrink_to_fit();
            close(socket_fd);
            exit(0);
        } else {
            std::cout << "File does not exist" << std::endl;
            path.clear(); // Clear the string to release memory
            path.shrink_to_fit();
            close(socket_fd);
            exit(1);
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        path.clear(); // Clear the string to release memory
        path.shrink_to_fit();
        close(socket_fd);
        exit(1);
    }
}

// Desc: handles a check command received over a socket connection. 
//It receives a file path from the client, checks if the file exists, and 
//sends an appropriate response back to the client.
//Pre: The connection_fd must be a valid connected socket file descriptor.
//Post: Function checks if the file exists using the stat function.
//An appropriate response has been sent back to the client. 
void handle_check_command(int connection_fd) {
    std::unique_ptr<char[]> path_cstr;    
    try {
        std::string path = recv_string(connection_fd);
        std::cout << "Received check comamnd for path: " << path << std::endl;

        path_cstr = std::make_unique<char[]>(path.size() + 1);
        std::strcpy(path_cstr.get(), path.c_str());
        std::string filename = basename(path_cstr.get());

        struct stat buffer;
        int stat_result = stat(path.c_str(), &buffer);
        if (stat_result == 0) {
            std::cout << "File exists: " << filename << std::endl;
            send_response(connection_fd, 0);
        } else {
            std::cout << "File does not exist: " << filename << std::endl;
            send_response(connection_fd, 1);
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        send_response(connection_fd, 1);
    }
}

//Desc: connects to a specified server, sends a command to load the 
//contents of a file at a given path, and handles the server's response. 
//Pre: ip parameter must be valid, port prameter must be valid port number, path must be a valid string
//Post: A command must be sent to the server. The specified file path has been sent to the server.
//If file exists, the function prints the file content and exits with status code 0. If not, it exits
//with status code 1.
void command_load(in_addr_t ip, in_port_t port, std::string& path) {
    int socket_fd = connect_to(ip, port);
    if (socket_fd < 0) {
        std::cout << "Failed to connect to server" << std::endl;
        exit(1);
    }
    uint32_t command = htonl(2);
    send_n(socket_fd, reinterpret_cast<const void *>(&command), sizeof(command), 0); 
    send_string(socket_fd, path);

    uint32_t response;
    try {
        recv_n(socket_fd, reinterpret_cast<void*>(&response), sizeof(response), 0);
        response = ntohl(response);

        if (response == 0) {
            std::string file_content = recv_string(socket_fd);
            std::cout << file_content;
            file_content.clear();
            file_content.shrink_to_fit();
            close(socket_fd);
            path.clear();
            path.shrink_to_fit();
            exit(0);
        } else {
            std::cout << "File does not exist" << std::endl;
            close(socket_fd);
            path.clear();
            path.shrink_to_fit();
            exit(1);
        }
    } catch (const std::runtime_error& e) {
        std::cout << "Error: " << e.what() << std::endl;
        close(socket_fd);
        path.clear();
        path.shrink_to_fit();
        exit(1);
    }
}

//Desc: handles a load command received over a socket connection. 
//It receives a file path from the client, reads the contents of the specified file.
//Pre: The connection_fd must be a valid connected socket file descriptor.
//Post: If the file exits, its content has been sent back to the client. 
//If the file does not exist or an error occurs, an error response has been sent 
//back to the client. 
void handle_load_command(int connection_fd) {
    try {
        std::string path = recv_string(connection_fd);
        std::cout << "Received load command for path: " << path << std::endl;

        std::ifstream file(path);
        if (!file) {
            send_error_response(connection_fd);
            std::cout << "File does not exist: " << path << std::endl;
            path.clear();
            path.shrink_to_fit();
            return;
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string file_content = buffer.str();
        file.close();

        uint32_t response = htonl(0); // Indicates success
        send_n(connection_fd, &response, sizeof(response), 0);
        send_string(connection_fd, file_content);

        file_content.clear();
        file_content.shrink_to_fit();
        path.clear();
        path.shrink_to_fit();
    } catch (const std::runtime_error& e) {
        std::cerr << "Error handling load command: " << e.what() << std::endl;
        send_error_response(connection_fd);
    }
}

//Desc: connects to a specified server, sends a command to 
//delete a file at a given path, and handles the server's response
//Pre: ip parameter must be valid, port prameter must be valid port number, path must be a valid string
//Post: If the file is deleted successfully, the function prints a success message and exits 
//with status code 0. If the file does not exist, it prints a message and exits with status code 1.
void command_delete(in_addr_t ip, in_port_t port, std::string& path) {
    int socket_fd = connect_to(ip, port);
    if (socket_fd < 0) {
        std::cout << "Failed to connect to server" << std::endl;
        exit(1);
    }

    bool success = false;
    try {
        uint32_t command = htonl(4);
        send_n(socket_fd, reinterpret_cast<const void*>(&command), sizeof(command), 0);
        send_string(socket_fd, path);

        uint32_t response;
        recv_n(socket_fd, reinterpret_cast<void*>(&response), sizeof(response), 0);
        response = ntohl(response);

        if (response == 0) {
            std::cout << "File successfully deleted" << std::endl;
            success = true;
        } else {
            std::cerr << "Failed to delete file." << std::endl;
        }

    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    // Ensure the socket is closed before exiting the function
    close(socket_fd);
    path.clear();
    path.shrink_to_fit();

    if(success) {
        exit(0);
    } else {
        exit(1);
    }
}

//Desc: handles a delete command received over a socket connection.
//Pre: The connection_fd must be a valid connected socket file descriptor.
//Post: A response indicating the result has been sent back to the client.
//If an error occurs during receiving or deleting a file, a failure
//response is sent to the client. 
void handle_delete_command(int connection_fd) {
    char *path_cstr = nullptr;
    try {
        std::string path = recv_string(connection_fd);
        std::cout << "Received delete command for path: " << path << std::endl;

        path_cstr = strdup(path.c_str());
        std::string filename = basename(path_cstr);

        uint32_t response;
        if (remove(path.c_str()) == 0) {
            std::cout << "File successfully deleted: " << filename << std::endl;
            response = htonl(0);
        } else {
            std::cout << "Error deleting file: " << filename << std::endl;
            response = htonl(1);
        }
        send_n(connection_fd, &response, sizeof(response), 0);
        free(path_cstr);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error handling delete command: " << e.what() << std::endl;
        uint32_t response = htonl(1);
        send_n(connection_fd, &response, sizeof(response), 0);
        
        if (path_cstr) {
        free(path_cstr);
        }
    }
    close(connection_fd);
}

//Desc: connects to a specified server, sends a command to 
//store the content provided by the user at a given path, and handles the server's response
//Pre: ip parameter must be valid, port prameter must be valid port number, path must be a valid string
//Post: A response from the server has been received and interpreted. If the file is successfully
//written, the function prints a success message and exits with status code 0. If the operation fails, 
//it exits with status code 1.
void command_store(in_addr_t ip, in_port_t port, std::string& path) {
    int socket_fd = connect_to(ip, port);
    if (socket_fd < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        exit(1);
    }

    try {
        uint32_t command = htonl(3); // Command code for 'store'
        send_n(socket_fd, reinterpret_cast<const void *>(&command), sizeof(command), 0);
        std::cout << "Sending path to server: " << path << std::endl;
        send_string(socket_fd, path);

        std::string line;
        while (std::getline(std::cin, line)) {
            line += "\n"; // Append newline since getline removes it
            send_string(socket_fd, line);
        }

        send_string(socket_fd, ""); // Indicate end of data with an empty string

        uint32_t response;
        recv_n(socket_fd, reinterpret_cast<void*>(&response), sizeof(response), 0);
        response = ntohl(response);

        if (response == 0) {
            std::cout << "File successfully written" << std::endl;
        } else {
            std::cerr << "Failed to write file" << std::endl;
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    close(socket_fd);
    path.clear();
    path.shrink_to_fit();
}

//Desc: handles a store command received over a socket connection.
//Pre: The connection_fd must be a valid connected socket file descriptor.
//Post: Data is received from the client and is written to the file until an 
//empty string is received. A response indicating the result has been sent back 
//to the client. 
void handle_store_command(int connection_fd) {
    FILE *file = nullptr;
    try {
        std::string path = recv_string(connection_fd);
        std::cout << "Received store command for path: " << path << std::endl;

        file = fopen(path.c_str(), "ab");
        if (!file) {
            uint32_t response = htonl(1);
            send_n(connection_fd, &response, sizeof(response), 0);
            std::cerr << "Error opening file for writing: " << path << std::endl;
            close(connection_fd);
            return;
        }

        while (true) {
            std::string data = recv_string(connection_fd);
            if (data.empty()) {
                break;
            }
            fwrite(data.c_str(), 1, data.size(), file);
        }

        fclose(file);
        file = nullptr;

        uint32_t response = htonl(0);
        send_n(connection_fd, &response, sizeof(response), 0);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error handling store command: " << e.what() << std::endl;
        uint32_t response = htonl(1); // Indicates failure
        send_n(connection_fd, &response, sizeof(response), 0);
    }
    
    if (file) {
        fclose(file);
    }

    close(connection_fd);
}


//Desc:  handles client requests by receiving a command from the client and 
//then delegating the command to the appropriate handler function.
//Pre: connection_fd must be a valid socket file descriptor
//Post: The appropriate handler function has been called based on the 
//command received.
void handle_client(int connection_fd) {
     try {
        uint32_t command;
        recv_n(connection_fd, &command, sizeof(command), 0);
        command = ntohl(command);

        //Handling each command for the program
        if (command == 1) {
            handle_check_command(connection_fd);
        } else if (command == 2) {
            handle_load_command(connection_fd);
        } else if (command == 3) {
            handle_store_command(connection_fd);
        } else if (command == 4) {
            handle_delete_command(connection_fd);
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    close(connection_fd);
}

// desc : Connects to server and sends a one-line message
// pre  : ip is a vaid ip address and port is a valid port number
// post : If an error is encountered, a runtime exception is thrown
void client(in_addr_t ip, in_port_t port) {

    // Attempt to connect to server through a new socket.
    // Return early if this fails.
    int socket_fd = connect_to(ip,port);
    if(socket_fd < 0) {
        return;
    }

    // Get a one-line message from the user
    std::string message;
    std::getline(std::cin,message);

    // Transmit message size ahead of time, so server can
    // pre-allocate message storage
    uint32_t message_size = message.size();
    send(socket_fd,&message_size,sizeof(message_size),0);

    // Transmit message
    send(socket_fd,message.c_str(),message.size(),0);

    // close connection
    close(socket_fd);
}

void signal_handler(int signal) {
    std::lock_guard<std::mutex> lock(stop_mutex);
    stop_flag = true;
    stop_cv.notify_all();
}

// desc : Listens on an arbitrary port (announced through stdout)
//        for connections, recieving messages as 32-bit string
//        lengths followed my a sequence of characters matching that
//        length.
// pre  : None
// post : If a listening socket cannot be set up, a runtime exception
//        is thrown. If a connection fails or disconnects early, the
//        error is announced but the server continues operation.
void server() {

    // Set up signal handling to ensure server is stopped gracefully
    struct sigaction sa;
    sa.sa_handler = signal_handler;  // Signal handler function
    sigemptyset(&sa.sa_mask);        // Initialize signal set to empty
    sa.sa_flags = 0;                 // No special flags
    sigaction(SIGINT, &sa, nullptr); // Set up SIGINT signal handler (e.g., for Ctrl+C)

    // Create a socket bound to an arbitrary port
    int socket_fd = arbitrary_socket();
    int port = get_port(socket_fd);

    std::cout << "Setup server at port " << port << std::endl;

    // Listen for incoming connections with a queue size of 1
    int status = listen(socket_fd, 1);
    if (status < 0) {
        std::cerr << "Listening failed." << std::endl;
        return;
    }

    fd_set readfds;
    sockaddr_storage storage;
    socklen_t socket_len = sizeof(sockaddr_storage);

    while (true) {
        // Clear the set and add the listening socket
        FD_ZERO(&readfds);
        FD_SET(socket_fd, &readfds);
        int max_fd = socket_fd;

        // Set timeout for select function
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &readfds, nullptr, nullptr, &timeout);
        if (activity < 0 && errno != EINTR) {
            std::cerr << "Select error." << std::endl;
            break;
        }

        // Check if the server should stop (signal received)
        {
            std::lock_guard<std::mutex> lock(stop_mutex);
            if (stop_flag.load()) {
                break;
            }
        }

        // Check if there is an incoming connection
        if (activity > 0 && FD_ISSET(socket_fd, &readfds)) {
            int connection_fd = accept(socket_fd, (sockaddr*)&storage, &socket_len);
            if (connection_fd < 0) {
                if (stop_flag.load()) {
                    break;
                }
                std::cerr << "Could not accept connection." << std::endl;
                continue;
            }

            // Handle the client connection in a new thread
            std::thread client_thread(handle_client, connection_fd);
            client_thread.detach();
        }
    }

    close(socket_fd);
}
