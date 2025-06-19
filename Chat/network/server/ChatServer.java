package Chat.network.server;

import Chat.common.Config;
import Chat.common.Logger;
import Chat.common.exceptions.NetworkException;
import Chat.crypto.KeyManager;
import Chat.crypto.SecureMessageProcessor;
import Chat.network.message.Message;
import Chat.network.message.SecureMessage;
import Chat.network.message.PlainTextMessage;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Server implementation for the chat application
 */
public class ChatServer {
    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private boolean running = false;
    private final List<ClientConnection> clients = new ArrayList<>();
    
    // Security components
    private KeyManager keyManager;
    private SecureMessageProcessor messageProcessor;
    
    // Callbacks
    private Consumer<String> logCallback;
    private Consumer<String> securityLogCallback;
    private Runnable clientListUpdatedCallback;
    
    // Logger
    private Logger logger;
    
    /**
     * Create a new chat server
     * 
     * @param logger The logger to use
     */
    public ChatServer(Logger logger) {
        this.logger = logger;
        this.keyManager = new KeyManager();
        this.messageProcessor = new SecureMessageProcessor(keyManager);
        this.threadPool = Executors.newCachedThreadPool();
    }
    
    /**
     * Start the server
     * 
     * @param port The port to listen on
     * @throws NetworkException if the server fails to start
     */
    public void start(int port) throws NetworkException {
        if (running) {
            throw new NetworkException("Server is already running");
        }
        
        try {
            // Initialize security
            try {
                keyManager.initializeKeyPair();
                logger.security("Generated server RSA key pair");
                
                if (securityLogCallback != null) {
                    String pubKeyStr = Chat.crypto.CryptoUtil.publicKeyToString(keyManager.getLocalPublicKey());
                    String privKeyStr = Chat.crypto.CryptoUtil.privateKeyToString(keyManager.getLocalPrivateKey());
                    
                    securityLogCallback.accept("Generated RSA key pair:");
                    securityLogCallback.accept("Public Key: " + pubKeyStr.substring(0, Math.min(40, pubKeyStr.length())) + "...");
                    securityLogCallback.accept("Private Key: " + privKeyStr.substring(0, Math.min(40, privKeyStr.length())) + "...");
                }
            } catch (Exception e) {
                logger.error("Failed to initialize security: " + e.getMessage());
                
                if (securityLogCallback != null) {
                    securityLogCallback.accept("Security initialization failed: " + e.getMessage());
                }
            }
            
            // Create server socket
            serverSocket = new ServerSocket(port);
            running = true;
            
            logger.info("Server started on port " + port);
            
            // Start accepting client connections
            threadPool.execute(this::acceptClients);
            
        } catch (IOException e) {
            throw new NetworkException("Failed to start server: " + e.getMessage(), e);
        }
    }
    
    /**
     * Accept client connections
     */
    private void acceptClients() {
        try {
            while (running) {
                try {
                    // Wait for a client connection
                    Socket clientSocket = serverSocket.accept();
                    
                    logger.info("Client connected: " + clientSocket.getInetAddress().getHostAddress());
                    
                    // Create a client connection handler
                    ClientConnection clientConnection = new ClientConnection(
                        clientSocket, 
                        this, 
                        keyManager,
                        messageProcessor,
                        logger
                    );
                    
                    // Add to clients list
                    synchronized (clients) {
                        clients.add(clientConnection);
                    }
                    
                    // Notify of client list update
                    if (clientListUpdatedCallback != null) {
                        clientListUpdatedCallback.run();
                    }
                    
                    // Start the client handler
                    threadPool.execute(clientConnection);
                    
                } catch (Exception e) {
                    if (running) {
                        logger.error("Error accepting client connection: " + e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            if (running) {
                logger.error("Server accept loop terminated: " + e.getMessage());
            }
        }
    }
    
    /**
     * Stop the server
     */
    public void stop() {
        if (!running) {
            return;
        }
        
        running = false;
        
        try {
            // Close all client connections
            synchronized (clients) {
                for (ClientConnection client : new ArrayList<>(clients)) {
                    client.close();
                }
                clients.clear();
            }
            
            // Close server socket
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            
            // Shut down thread pool
            threadPool.shutdown();
            
            logger.info("Server stopped");
            
            // Notify of client list update
            if (clientListUpdatedCallback != null) {
                clientListUpdatedCallback.run();
            }
            
        } catch (IOException e) {
            logger.error("Error stopping server: " + e.getMessage());
        }
    }
    
    /**
     * Broadcast a message to all clients
     * 
     * @param message The message
     * @param sender The sending client (null for system messages)
     */
    public void broadcast(String message, ClientConnection sender) {
        synchronized (clients) {
            for (ClientConnection client : clients) {
                // Don't send the message back to the sender
                if (client != sender) {
                    client.sendMessage(message, 
                        sender != null ? sender.getClientName() : "SERVER");
                }
            }
        }
    }
    
    /**
     * Remove a client from the server
     * 
     * @param client The client to remove
     */
    public void removeClient(ClientConnection client) {
        synchronized (clients) {
            clients.remove(client);
        }
        
        logger.info("Client disconnected: " + client.getClientName());
        
        // Notify of client list update
        if (clientListUpdatedCallback != null) {
            clientListUpdatedCallback.run();
        }
    }
    
    /**
     * Kick a client from the server
     * 
     * @param index The index of the client to kick
     */
    public void kickClient(int index) {
        synchronized (clients) {
            if (index >= 0 && index < clients.size()) {
                ClientConnection client = clients.get(index);
                client.sendMessage("You have been kicked from the server", "SERVER");
                client.close();
            }
        }
    }
    
    /**
     * Get a list of all connected clients
     * 
     * @return List of client information strings
     */
    public List<String> getClientList() {
        List<String> clientList = new ArrayList<>();
        
        synchronized (clients) {
            for (ClientConnection client : clients) {
                clientList.add(client.getClientName() + " (" + 
                               client.getClientAddress() + ")");
            }
        }
        
        return clientList;
    }
    
    /**
     * Send a broadcast message from the server to all clients
     * 
     * @param message The message to broadcast
     */
    public void broadcastFromServer(String message) {
        synchronized (clients) {
            for (ClientConnection client : clients) {
                client.sendMessage(message, "SERVER");
            }
        }
        
        logger.info("Broadcast: " + message);
    }
    
    /**
     * Set the callback for client list updates
     * 
     * @param callback The callback function
     */
    public void setClientListUpdatedCallback(Runnable callback) {
        this.clientListUpdatedCallback = callback;
    }
    
    /**
     * Check if the server is running
     * 
     * @return true if the server is running
     */
    public boolean isRunning() {
        return running;
    }
}
