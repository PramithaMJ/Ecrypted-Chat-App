package ChatV1;

import java.io.Serializable;

/**
 * Represents a secure message in the chat system
 * Used for transmitting encrypted messages and keys
 */
public class SecureMessage implements Serializable {
    private static final long serialVersionUID = 1L;
    
    public enum MessageType {
        PUBLIC_KEY_EXCHANGE,     // For exchanging public keys
        SYMMETRIC_KEY_EXCHANGE,  // For transmitting the encrypted AES key
        ENCRYPTED_MESSAGE,       // Normal encrypted chat messages
        AUTH_CHALLENGE,          // Authentication challenge
        AUTH_RESPONSE,           // Authentication response
        AUTH_SUCCESS,            // Authentication successful
        AUTH_FAILED              // Authentication failed
    }
    
    private MessageType type;
    private String sender;
    private String content;
    private String signature;    // Optional: Digital signature for authentication
    
    public SecureMessage(MessageType type, String sender, String content) {
        this.type = type;
        this.sender = sender;
        this.content = content;
        this.signature = null;
    }
    
    public SecureMessage(MessageType type, String sender, String content, String signature) {
        this.type = type;
        this.sender = sender;
        this.content = content;
        this.signature = signature;
    }
    
    public MessageType getType() {
        return type;
    }
    
    public String getSender() {
        return sender;
    }
    
    public String getContent() {
        return content;
    }
    
    public String getSignature() {
        return signature;
    }
    
    public void setSignature(String signature) {
        this.signature = signature;
    }
    
    @Override
    public String toString() {
        // Format the message for display
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(type).append("] ");
        sb.append("From: ").append(sender).append("\n");
        sb.append("Content: ").append(content);
        if (signature != null) {
            sb.append("\nSigned: Yes");
        }
        return sb.toString();
    }
    
    /**
     * Convert to a formatted string for logging/display
     */
    public String toDisplayString() {
        switch (type) {
            case PUBLIC_KEY_EXCHANGE:
                return "[SECURITY] Public key exchange from " + sender;
                
            case SYMMETRIC_KEY_EXCHANGE:
                return "[SECURITY] AES key exchange from " + sender;
                
            case ENCRYPTED_MESSAGE:
                return sender + ": [Encrypted Message]";
                
            case AUTH_CHALLENGE:
                return "[AUTH] Challenge from " + sender;
                
            case AUTH_RESPONSE:
                return "[AUTH] Response from " + sender;
                
            case AUTH_SUCCESS:
                return "[AUTH] Authentication successful for " + sender;
                
            case AUTH_FAILED:
                return "[AUTH] Authentication failed for " + sender;
                
            default:
                return "[SECURITY] Unknown message type from " + sender;
        }
    }
    
    /**
     * Parse a secure message string back to object
     */
    public static SecureMessage parseFromString(String messageStr) {
        String[] parts = messageStr.split("\\|");
        MessageType type = MessageType.valueOf(parts[0]);
        String sender = parts[1];
        String content = parts[2];
        String signature = null;
        if (parts.length > 3) {
            signature = parts[3];
        }
        return new SecureMessage(type, sender, content, signature);
    }
    
    /**
     * Convert the secure message to a string for transmission
     */
    public String toTransmissionString() {
        StringBuilder sb = new StringBuilder();
        sb.append(type.toString()).append("|");
        sb.append(sender).append("|");
        sb.append(content);
        if (signature != null) {
            sb.append("|").append(signature);
        }
        return sb.toString();
    }
}
