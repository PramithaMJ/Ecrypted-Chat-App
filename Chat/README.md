# Secure Chat Application

A secure chat application with client-server architecture implemented in Java. The application features a hybrid cryptosystem combining symmetric and asymmetric encryption with two-way authentication.

## Features

- Client-server architecture using Java Sockets
- GUI interface using Java Swing
- Hybrid cryptosystem (RSA 2048-bit + AES 256-bit)
- Two-way authentication
- Digital signatures for message verification
- Real-time display of cryptographic elements

## Project Structure

```
Chat/
├── common/           # Common utilities and interfaces
│   ├── Config.java   # Application constants and configuration
│   ├── Logger.java   # Logging utility
│   └── exceptions/   # Custom exceptions
│       └── ...
├── crypto/           # Cryptographic components
│   ├── CryptoUtil.java           # Core cryptographic utilities
│   ├── KeyManager.java          # Key management operations
│   └── SecureMessageProcessor.java # Message encryption/decryption
├── network/          # Networking components
│   ├── message/      # Message models
│   │   ├── Message.java         # Base message interface
│   │   ├── SecureMessage.java   # Secure message implementation
│   │   └── ...
│   ├── client/       # Client-side networking
│   │   ├── ChatClient.java      # Client implementation
│   │   └── ClientHandler.java   # Client connection handler
│   └── server/       # Server-side networking
│       ├── ChatServer.java      # Server implementation
│       └── ClientConnection.java # Server-side client connection
└── ui/               # User interface components
    ├── client/       # Client UI
    │   ├── ChatClientGUI.java   # Client GUI implementation
    │   └── ...
    └── server/       # Server UI
        ├── ChatServerGUI.java   # Server GUI implementation
        └── ...
```

## Getting Started

1. Start the server application by running `ChatServerGUI.java`
2. Start one or more client instances by running `ChatClientGUI.java`
3. Connect the clients to the server
4. Enjoy secure messaging!

## Security Details

- **RSA Key Size**: 2048 bits
- **AES Key Size**: 256 bits
- **Authentication**: Challenge-response using digital signatures
- **Digital Signatures**: SHA-256 with RSA
