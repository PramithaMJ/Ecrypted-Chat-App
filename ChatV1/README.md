# Secure Chat Application (v1)

A secure chat application with client-server architecture implemented in Java. This is the original implementation of the chat application featuring a hybrid cryptographic system.

## Features

- Client-server architecture using Java Sockets
- GUI interface using Java Swing
- Hybrid cryptosystem (RSA 2048-bit + AES 256-bit)
- Two-way authentication
- Digital signatures for message verification
- Real-time display of cryptographic elements

## Components

- `ChatClient.java` - Basic console-based client implementation
- `ChatServer.java` - Basic console-based server implementation
- `ChatClientGUI.java` - GUI implementation for the client
- `ChatServerGUI.java` - GUI implementation for the server
- `CryptoUtil.java` - Cryptographic utilities for secure communication
- `SecureMessage.java` - Message format for secure communication

## How to Run

### Running the Server

```bash
javac ChatV1.ChatServerMain
java ChatServerMain
```

### Running the Client

```bash
javac ChatV1/ChatClientGUI.java
java ChatV1/ChatClientGUI
```

## Security Details

- **RSA Key Size**: 2048 bits
- **AES Key Size**: 256 bits
- **Authentication**: Challenge-response using digital signatures
- **Digital Signatures**: SHA-256 with RSA

## Usage Instructions

1. Start the server application by running `ChatServerGUI`
2. Click the "Start Server" button
3. Start one or more client instances by running `ChatClientGUI`
4. In the client, click "Connect" to connect to the server
5. Start sending messages!

The GUI displays cryptographic information in a separate pane, showing all security operations and status in real time.

## Note

This is the original version of the chat application. An improved, restructured version is available in the parent directory.
