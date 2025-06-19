package Chat.network.server;

import Chat.common.Logger;
import Chat.common.exceptions.CryptoException;
import Chat.crypto.KeyManager;
import Chat.crypto.SecureMessageProcessor;
import Chat.network.message.SecureMessage;
import Chat.network.message.PlainTextMessage;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;

/**
 * Handles a client connection on the server side
 */
public class ClientConnection implements Runnable {
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private String clientName;
    private String clientAddress;
    private ChatServer server;
    
    // Security components
    private KeyManager keyManager;
    private SecureMessageProcessor messageProcessor;
    private boolean secureConnectionEstablished = false;
    private String authenticationChallenge;
    
    // Logger
    private Logger logger;
    
    /**
     * Create a new client connection
     * 
     * @param socket The client socket
     * @param server The chat server
     * @param keyManager The key manager
     * @param messageProcessor The secure message processor
     * @param logger The logger
     */
    public ClientConnection(
            Socket socket, 
            ChatServer server, 
            KeyManager keyManager,
            SecureMessageProcessor messageProcessor,
            Logger logger) {
        this.socket = socket;
        this.server = server;
        this.clientAddress = socket.getInetAddress().getHostAddress();
        this.clientName = "Client-" + clientAddress;
        this.keyManager = keyManager;
        this.messageProcessor = messageProcessor;
        this.logger = logger;
    }
    
    @Override
    public void run() {
        try {
            // Set up input and output streams
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            // Send welcome message
            sendMessage("Welcome to the Chat Server! Your default name is: " + clientName, "SERVER");
            sendMessage("Type 'NAME: your_name' to set your name.", "SERVER");
            
            // Process messages from this client
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                // Process the message
                processIncomingMessage(inputLine);
            }
        } catch (IOException e) {
            // Connection was closed
            logger.info("Client connection closed: " + clientName);
        } finally {
            close();
        }
    }
    
    /**
     * Process an incoming message from the client
     */
    private void processIncomingMessage(String messageStr) {
        try {
            // Check if this is a secure message
            if (messageStr.contains("|")) {
                SecureMessage secureMessage = SecureMessage.parseFromString(messageStr);
                processSecureMessage(secureMessage);
            } else {
                // Regular, non-secure message
                PlainTextMessage plainMessage = PlainTextMessage.parseFromString(messageStr, clientName);
                
                // Handle based on message type
                switch (plainMessage.getType()) {
                    case NAME_CHANGE:
                        String newName = plainMessage.getContent().trim();
                        if (!newName.isEmpty()) {
                            // Announce the name change
                            server.broadcast(clientName + " has changed their name to " + newName, null);
                            logger.info(clientName + " changed name to " + newName);
                            clientName = newName;
                            sendMessage("Name changed to: " + clientName, "SERVER");
                        }
                        break;
                        
                    case CHAT_MESSAGE:
                        // Log the message
                        logger.info(clientName + ": " + plainMessage.getContent());
                        
                        // Broadcast to other clients
                        server.broadcast(plainMessage.getContent(), this);
                        break;
                        
                    case COMMAND:
                        // Handle commands
                        logger.info(clientName + " issued command: " + plainMessage.getContent());
                        // Add command processing here if needed
                        break;
                        
                    default:
                        // Unrecognized message type
                        logger.info("Received unrecognized message type from " + clientName);
                }
            }
        } catch (Exception e) {
            logger.error("Error processing message from " + clientName + ": " + e.getMessage());
        }
    }
    
    /**
     * Process different types of secure messages
     */
    private void processSecureMessage(SecureMessage message) {
        try {
            switch (message.getType()) {
                case PUBLIC_KEY_EXCHANGE:
                    // Client is sending their public key
                    logger.security("Received public key from " + clientName);
                    
                    // Store the client's public key
                    PublicKey clientPublicKey = Chat.crypto.CryptoUtil.stringToPublicKey(message.getContent());
                    keyManager.storePeerPublicKey(clientName, clientPublicKey);
                    
                    // Send our public key back
                    SecureMessage keyResponse = new SecureMessage(
                        SecureMessage.MessageType.PUBLIC_KEY_EXCHANGE,
                        "SERVER",
                        Chat.crypto.CryptoUtil.publicKeyToString(keyManager.getLocalPublicKey())
                    );
                    out.println(keyResponse.toTransmissionString());
                    logger.security("Sent server public key to " + clientName);
                    
                    // Generate and send an authentication challenge
                    SecureMessage challengeMsg = messageProcessor.createAuthChallenge("SERVER");
                    authenticationChallenge = challengeMsg.getContent();
                    out.println(challengeMsg.toTransmissionString());
                    logger.security("Sent authentication challenge to " + clientName);
                    break;
                    
                case SYMMETRIC_KEY_EXCHANGE:
                    // Client is sending an encrypted AES key
                    logger.security("Received encrypted session key from " + clientName);
                    
                    try {
                        // Decrypt the session key using our private key
                        byte[] decryptedKeyBytes = Chat.crypto.CryptoUtil.decryptRSA(
                            message.getContent(), 
                            keyManager.getLocalPrivateKey()
                        );
                        
                        // Store the session key
                        SecretKey sessionKey = new javax.crypto.spec.SecretKeySpec(
                            decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES"
                        );
                        keyManager.storeSessionKey(clientName, sessionKey);
                        
                        logger.security("Stored session key for " + clientName);
                        
                        // Verify the signature if provided
                        if (message.getSignature() != null) {
                            boolean verified = Chat.crypto.CryptoUtil.verify(
                                message.getContent(),
                                message.getSignature(),
                                keyManager.getPeerPublicKey(clientName)
                            );
                            
                            if (verified) {
                                logger.security("Verified signature on key from " + clientName);
                            } else {
                                logger.security("WARNING: Key signature verification failed for " + clientName);
                            }
                        }
                    } catch (Exception e) {
                        logger.error("Failed to process session key from " + clientName + ": " + e.getMessage());
                    }
                    break;
                    
                case AUTH_RESPONSE:
                    // Client is responding to our authentication challenge
                    logger.security("Received authentication response from " + clientName);
                    
                    try {
                        // Verify the response
                        boolean verified = messageProcessor.verifyAuthResponse(
                            authenticationChallenge, 
                            message
                        );
                        
                        if (verified) {
                            // Authentication successful
                            logger.security("Authentication successful for " + clientName);
                            secureConnectionEstablished = true;
                            
                            // Send authentication success message
                            SecureMessage successMsg = new SecureMessage(
                                SecureMessage.MessageType.AUTH_SUCCESS,
                                "SERVER",
                                "Authentication successful, secure connection established"
                            );
                            out.println(successMsg.toTransmissionString());
                        } else {
                            // Authentication failed
                            logger.security("Authentication failed for " + clientName);
                            
                            SecureMessage failedMsg = new SecureMessage(
                                SecureMessage.MessageType.AUTH_FAILED,
                                "SERVER",
                                "Authentication failed, connection will be insecure"
                            );
                            out.println(failedMsg.toTransmissionString());
                        }
                    } catch (Exception e) {
                        logger.error("Failed to verify authentication response: " + e.getMessage());
                    }
                    break;
                    
                case ENCRYPTED_MESSAGE:
                    // Received an encrypted message
                    try {
                        if (!keyManager.hasSessionWith(clientName)) {
                            logger.error("Received encrypted message from " + clientName + " but no session established");
                            return;
                        }
                        
                        // Decrypt the message
                        String decryptedMsg = messageProcessor.decryptMessage(message);
                        
                        // Verify the signature if present
                        boolean verified = false;
                        if (message.getSignature() != null) {
                            verified = messageProcessor.verifyMessageSignature(message, decryptedMsg);
                        }
                        
                        // Log the decrypted message
                        logger.info(clientName + ": " + decryptedMsg + (verified ? " [Verified]" : ""));
                        
                        // Broadcast to all other clients
                        server.broadcast(decryptedMsg, this);
                        
                        logger.security("Processed encrypted message from " + clientName +
                                       (verified ? " (signature verified)" : " (unsigned or unverified)"));
                    } catch (Exception e) {
                        logger.error("Failed to process encrypted message: " + e.getMessage());
                    }
                    break;
                    
                default:
                    logger.security("Received unknown secure message type from " + clientName + ": " + message.getType());
                    break;
            }
        } catch (Exception e) {
            logger.error("Error processing secure message from " + clientName + ": " + e.getMessage());
        }
    }
    
    /**
     * Send a message to the client
     * 
     * @param message The message content
     * @param sender The sender name
     */
    public void sendMessage(String message, String sender) {
        if (out != null) {
            // If we have a secure connection and a session key, encrypt the message
            if (secureConnectionEstablished && keyManager.hasSessionWith(clientName)) {
                try {
                    // Create encrypted message
                    SecureMessage secureMsg = messageProcessor.encryptMessage(message, clientName, sender);
                    
                    // Send the encrypted message
                    out.println(secureMsg.toTransmissionString());
                    logger.security("Sent encrypted message to " + clientName);
                } catch (CryptoException e) {
                    logger.error("Failed to encrypt message for " + clientName + ": " + e.getMessage());
                    
                    // Fall back to unencrypted if encryption fails
                    sendPlainTextMessage(message, sender);
                }
            } else {
                // Send unencrypted if we don't have a secure connection
                sendPlainTextMessage(message, sender);
            }
        }
    }
    
    /**
     * Send a plain text message to the client
     * 
     * @param message The message content
     * @param sender The sender name
     */
    private void sendPlainTextMessage(String message, String sender) {
        if (sender.equals("SERVER")) {
            out.println(message);
        } else {
            out.println(sender + ": " + message);
        }
    }
    
    /**
     * Close the client connection
     */
    public void close() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            
            // Remove this client from the server
            server.removeClient(this);
        } catch (IOException e) {
            logger.error("Error closing client socket: " + e.getMessage());
        }
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
     * Get the client's address
     * 
     * @return the client's IP address
     */
    public String getClientAddress() {
        return clientAddress;
    }
    
    /**
     * Check if the client has a secure connection
     * 
     * @return true if the connection is secure
     */
    public boolean isSecureConnection() {
        return secureConnectionEstablished;
    }
}
