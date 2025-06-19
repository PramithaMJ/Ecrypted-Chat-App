package Chat.network.message;

/**
 * Represents a plain text message in the chat system
 */
public class PlainTextMessage implements Message {
    private String sender;
    private String content;
    private MessageType type;
    
    public enum MessageType {
        CHAT_MESSAGE,   // Regular chat message
        SYSTEM_MESSAGE, // System notification
        NAME_CHANGE,    // User changing their name
        COMMAND         // Command to the server
    }
    
    public PlainTextMessage(String sender, String content, MessageType type) {
        this.sender = sender;
        this.content = content;
        this.type = type;
    }
    
    @Override
    public String getSender() {
        return sender;
    }
    
    @Override
    public String getContent() {
        return content;
    }
    
    public MessageType getType() {
        return type;
    }
    
    @Override
    public String toTransmissionString() {
        if (type == MessageType.NAME_CHANGE) {
            return "NAME: " + content;
        } else if (type == MessageType.COMMAND) {
            return "CMD: " + content;
        } else {
            return content;
        }
    }
    
    @Override
    public String toDisplayString() {
        switch (type) {
            case SYSTEM_MESSAGE:
                return "[SYSTEM] " + content;
            case CHAT_MESSAGE:
                return sender + ": " + content;
            case NAME_CHANGE:
                return sender + " changed name to " + content;
            case COMMAND:
                return "[COMMAND] " + content;
            default:
                return content;
        }
    }
    
    /**
     * Parse a string into the appropriate message type
     */
    public static PlainTextMessage parseFromString(String messageStr, String defaultSender) {
        if (messageStr.startsWith("NAME:")) {
            String newName = messageStr.substring(5).trim();
            return new PlainTextMessage(defaultSender, newName, MessageType.NAME_CHANGE);
        } else if (messageStr.startsWith("CMD:")) {
            String command = messageStr.substring(4).trim();
            return new PlainTextMessage(defaultSender, command, MessageType.COMMAND);
        } else {
            return new PlainTextMessage(defaultSender, messageStr, MessageType.CHAT_MESSAGE);
        }
    }
}
