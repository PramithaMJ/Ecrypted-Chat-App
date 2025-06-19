package Chat.network.client;

import Chat.common.Config;
import Chat.common.Logger;
import Chat.common.exceptions.NetworkException;
import Chat.crypto.KeyManager;
import Chat.crypto.SecureMessageProcessor;
import Chat.network.message.Message;
import Chat.network.message.SecureMessage;
import Chat.network.message.PlainTextMessage;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Client implementation for the chat application
 */
public class ChatClient {
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private boolean connected = false;
    private String clientName;
    private ExecutorService executor;
    
    // Security components
    private KeyManager keyManager;
    private SecureMessageProcessor messageProcessor;
    private boolean secureConnectionEstablished = false;
    private String authenticationChallenge;
    
    // Callbacks for message handling
    private Consumer<String> messageCallback;
    private Consumer<String> securityCallback;
    private Consumer<Boolean> connectionStatusCallback;
    private Consumer<Boolean> securityStatusCallback;
    
    // Logger
    private Logger logger;
    
    /**
     * Create a new chat client
     * 
     * @param clientName The name of this client
     * @param logger The logger to use
     */
    public ChatClient(String clientName, Logger logger) {
        this.clientName = clientName;
        this.logger = logger;
        this.executor = Executors.newSingleThreadExecutor();
        this.keyManager = new KeyManager();
        this.messageProcessor = new SecureMessageProcessor(keyManager);
    }
    
    /**
     * Connect to a chat server
     * 
     * @param serverAddress The server address
     * @param port The server port
     * @throws NetworkException if connection fails
     */
    public void connect(String serverAddress, int port) throws NetworkException {
        if (connected) {
            throw new NetworkException("Already connected to server");
        }
        
        try {
            // Create socket and streams
            socket = new Socket(serverAddress, port);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            connected = true;
            
            // Notify connection status
            if (connectionStatusCallback != null) {
                connectionStatusCallback.accept(true);
            }
            
            logger.info("Connected to server at " + serverAddress + ":" + port);
            
            // Initialize security
            try {
                setupSecureConnection();
            } catch (Exception e) {
                logger.error("Failed to establish secure connection: " + e.getMessage());
                if (securityCallback != null) {
                    securityCallback.accept("Secure connection failed: " + e.getMessage());
                }
            }
            
            // Start message listener
            startMessageListener();
            
        } catch (IOException e) {
            connected = false;
            throw new NetworkException("Failed to connect to server: " + e.getMessage(), e);
        }
    }
    
    /**
     * Start listening for incoming messages
     */
    private void startMessageListener() {
        executor.execute(() -> {
            try {
                String serverMessageStr;
                while (connected && (serverMessageStr = in.readLine()) != null) {
                    // Process the message
                    processIncomingMessage(serverMessageStr);
                }
            } catch (IOException e) {
                if (connected) {
                    logger.error("Connection error: " + e.getMessage());
                    disconnect();
                }
            }
        });
    }
    
    /**
     * Process an incoming message from the server
     */
    private void processIncomingMessage(String messageStr) {
        try {
            // Check if this is a secure message
            if (messageStr.contains("|")) {
                SecureMessage secureMessage = SecureMessage.parseFromString(messageStr);
                processSecureMessage(secureMessage);
            } else {
                // Regular, non-secure message
                PlainTextMessage plainMessage = PlainTextMessage.parseFromString(messageStr, "SERVER");
                
                if (messageCallback != null) {
                    messageCallback.accept(plainMessage.toDisplayString());
                }
            }
        } catch (Exception e) {
            logger.error("Error processing message: " + e.getMessage());
        }
    }
    
    /**
     * Process different types of secure messages
     */
    private void processSecureMessage(SecureMessage message) {
        try {
            switch (message.getType()) {
                case PUBLIC_KEY_EXCHANGE:
                    // Received server's public key
                    logger.security("Received server public key");
                    
                    if (securityCallback != null) {
                        securityCallback.accept("Received server public key");
                    }
                    
                    // Store the server's public key
                    keyManager.storePeerPublicKey("SERVER", 
                            Chat.crypto.CryptoUtil.stringToPublicKey(message.getContent()));
                    
                    // Generate a symmetric AES key for the session
                    keyManager.generateSessionKey("SERVER");
                    
                    if (securityCallback != null) {
                        securityCallback.accept("Generated AES Session Key");
                    }
                    
                    // Encrypt the AES key with the server's public key and send it
                    String encryptedKey = Chat.crypto.CryptoUtil.encryptRSA(
                        keyManager.getSessionKey("SERVER").getEncoded(), 
                        keyManager.getPeerPublicKey("SERVER")
                    );
                    
                    SecureMessage keyExchangeMsg = new SecureMessage(
                        SecureMessage.MessageType.SYMMETRIC_KEY_EXCHANGE,
                        clientName,
                        encryptedKey
                    );
                    
                    // Sign the key with our private key for authentication
                    keyExchangeMsg.setSignature(
                        Chat.crypto.CryptoUtil.sign(encryptedKey, keyManager.getLocalPrivateKey())
                    );
                    
                    // Send the encrypted key to the server
                    out.println(keyExchangeMsg.toTransmissionString());
                    
                    if (securityCallback != null) {
                        securityCallback.accept("Sent encrypted AES key to server");
                    }
                    break;
                    
                case AUTH_CHALLENGE:
                    // Server is challenging us to prove our identity
                    logger.security("Received authentication challenge from server");
                    
                    if (securityCallback != null) {
                        securityCallback.accept("Received auth challenge from server");
                    }
                    
                    // Store the challenge
                    authenticationChallenge = message.getContent();
                    
                    // Sign the challenge with our private key
                    SecureMessage authResponse = messageProcessor.createAuthResponse(
                        authenticationChallenge, 
                        clientName
                    );
                    
                    // Send the signed response
                    out.println(authResponse.toTransmissionString());
                    
                    if (securityCallback != null) {
                        securityCallback.accept("Sent authentication response");
                    }
                    break;
                    
                case AUTH_SUCCESS:
                    // Authentication successful
                    secureConnectionEstablished = true;
                    logger.security("Secure connection established with server");
                    
                    if (messageCallback != null) {
                        messageCallback.accept("Secure connection established with server!");
                    }
                    
                    if (securityCallback != null) {
                        securityCallback.accept("Authentication successful - secure connection established");
                    }
                    
                    // Update security status
                    if (securityStatusCallback != null) {
                        securityStatusCallback.accept(true);
                    }
                    break;
                    
                case AUTH_FAILED:
                    logger.security("Authentication failed: " + message.getContent());
                    
                    if (messageCallback != null) {
                        messageCallback.accept("Authentication failed: " + message.getContent());
                    }
                    
                    if (securityCallback != null) {
                        securityCallback.accept("Authentication failed: " + message.getContent());
                    }
                    break;
                    
                case ENCRYPTED_MESSAGE:
                    if (secureConnectionEstablished) {
                        // Decrypt the message
                        String decryptedMsg = messageProcessor.decryptMessage(message);
                        
                        // Display the decrypted message
                        if (messageCallback != null) {
                            messageCallback.accept(message.getSender() + ": " + decryptedMsg);
                        }
                        
                        // Verify signature if present
                        if (message.getSignature() != null) {
                            boolean verified = messageProcessor.verifyMessageSignature(message, decryptedMsg);
                            
                            if (securityCallback != null) {
                                securityCallback.accept("Received encrypted message from " + 
                                    message.getSender() + (verified ? " (signature verified)" : " (signature invalid)"));
                            }
                        } else {
                            if (securityCallback != null) {
                                securityCallback.accept("Received encrypted message from " + 
                                    message.getSender() + " (unsigned)");
                            }
                        }
                    } else {
                        logger.error("Received encrypted message but no secure connection established");
                        
                        if (securityCallback != null) {
                            securityCallback.accept("ERROR: Cannot decrypt message, no secure connection");
                        }
                    }
                    break;
                    
                default:
                    if (messageCallback != null) {
                        messageCallback.accept(message.toDisplayString());
                    }
                    
                    if (securityCallback != null) {
                        securityCallback.accept("Received message of type: " + message.getType());
                    }
                    break;
            }
        } catch (Exception e) {
            logger.error("Error processing secure message: " + e.getMessage());
            
            if (securityCallback != null) {
                securityCallback.accept("Error: " + e.getMessage());
            }
        }
    }
    
    /**
     * Set up secure connection with the server using a hybrid cryptosystem
     * 
     * @throws Exception if security setup fails
     */
    private void setupSecureConnection() throws Exception {
        // Generate RSA key pair for this client
        logger.security("Generating RSA key pair...");
        
        if (securityCallback != null) {
            securityCallback.accept("Generating RSA key pair...");
        }
        
        keyManager.initializeKeyPair();
        
        if (securityCallback != null) {
            String pubKeyStr = Chat.crypto.CryptoUtil.publicKeyToString(keyManager.getLocalPublicKey());
            String privKeyStr = Chat.crypto.CryptoUtil.privateKeyToString(keyManager.getLocalPrivateKey());
            
            securityCallback.accept("Client Public Key: " + pubKeyStr.substring(0, Math.min(40, pubKeyStr.length())) + "...");
            securityCallback.accept("Client Private Key: " + privKeyStr.substring(0, Math.min(40, privKeyStr.length())) + "...");
        }
        
        // Send our public key to the server
        SecureMessage keyMessage = new SecureMessage(
            SecureMessage.MessageType.PUBLIC_KEY_EXCHANGE,
            clientName,
            Chat.crypto.CryptoUtil.publicKeyToString(keyManager.getLocalPublicKey())
        );
        
        out.println(keyMessage.toTransmissionString());
        
        if (securityCallback != null) {
            securityCallback.accept("Sent public key to server");
        }
        
        // The rest of the authentication flow will be handled by the message listener
        if (messageCallback != null) {
            messageCallback.accept("Waiting for server public key...");
        }
    }
    
    /**
     * Send a message to the server
     * 
     * @param message The message to send
     * @return true if the message was sent successfully
     */
    public boolean sendMessage(String message) {
        if (!connected || out == null) {
            return false;
        }
        
        try {
            // If we have a secure connection, encrypt the message
            if (secureConnectionEstablished) {
                SecureMessage secureMsg = messageProcessor.encryptMessage(message, "SERVER", clientName);
                out.println(secureMsg.toTransmissionString());
                
                if (securityCallback != null) {
                    securityCallback.accept("Sent encrypted message: " + 
                        message.substring(0, Math.min(20, message.length())) + 
                        (message.length() > 20 ? "..." : ""));
                }
            } else {
                // Send the message unencrypted if no secure connection
                PlainTextMessage plainMsg = new PlainTextMessage(
                    clientName, 
                    message, 
                    PlainTextMessage.MessageType.CHAT_MESSAGE
                );
                
                out.println(plainMsg.toTransmissionString());
                
                if (securityCallback != null) {
                    securityCallback.accept("WARNING: Message sent unencrypted");
                }
            }
            
            return true;
        } catch (Exception e) {
            logger.error("Error sending message: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Set the client's name
     * 
     * @param newName The new name
     * @return true if the name was changed successfully
     */
    public boolean setName(String newName) {
        if (!connected || out == null || newName.trim().isEmpty()) {
            return false;
        }
        
        PlainTextMessage nameMsg = new PlainTextMessage(
            clientName,
            newName,
            PlainTextMessage.MessageType.NAME_CHANGE
        );
        
        out.println(nameMsg.toTransmissionString());
        clientName = newName;
        
        return true;
    }
    
    /**
     * Disconnect from the server
     */
    public void disconnect() {
        if (connected) {
            try {
                connected = false;
                secureConnectionEstablished = false;
                
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
                
                // Notify connection status
                if (connectionStatusCallback != null) {
                    connectionStatusCallback.accept(false);
                }
                
                // Notify security status
                if (securityStatusCallback != null) {
                    securityStatusCallback.accept(false);
                }
                
                logger.info("Disconnected from server");
            } catch (IOException e) {
                logger.error("Error while disconnecting: " + e.getMessage());
            }
        }
    }
    
    /**
     * Set the callback for receiving messages
     * 
     * @param callback The callback function
     */
    public void setMessageCallback(Consumer<String> callback) {
        this.messageCallback = callback;
    }
    
    /**
     * Set the callback for security-related messages
     * 
     * @param callback The callback function
     */
    public void setSecurityCallback(Consumer<String> callback) {
        this.securityCallback = callback;
    }
    
    /**
     * Set the callback for connection status changes
     * 
     * @param callback The callback function
     */
    public void setConnectionStatusCallback(Consumer<Boolean> callback) {
        this.connectionStatusCallback = callback;
    }
    
    /**
     * Set the callback for security status changes
     * 
     * @param callback The callback function
     */
    public void setSecurityStatusCallback(Consumer<Boolean> callback) {
        this.securityStatusCallback = callback;
    }
    
    /**
     * Check if the client is connected to a server
     * 
     * @return true if connected
     */
    public boolean isConnected() {
        return connected;
    }
    
    /**
     * Check if the client has a secure connection to the server
     * 
     * @return true if secure
     */
    public boolean isSecureConnection() {
        return secureConnectionEstablished;
    }
    
    /**
     * Get the client's name
     * 
     * @return the client name
     */
    public String getClientName() {
        return clientName;
    }
    
    /**
     * Clean up resources when shutting down
     */
    public void shutdown() {
        disconnect();
        executor.shutdown();
    }
}
