package Chat.network.message;

/**
 * Interface for all messages in the chat system
 */
public interface Message {
    /**
     * Get the sender of the message
     * @return the sender identifier
     */
    String getSender();
    
    /**
     * Get the content of the message
     * @return the message content
     */
    String getContent();
    
    /**
     * Convert the message to a string for transmission
     * @return the transmission string
     */
    String toTransmissionString();
    
    /**
     * Get a formatted string for display/logging
     * @return the display string
     */
    String toDisplayString();
}
