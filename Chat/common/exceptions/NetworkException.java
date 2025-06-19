package Chat.common.exceptions;

/**
 * Exception thrown when there is an issue with network operations
 */
public class NetworkException extends Exception {
    private static final long serialVersionUID = 1L;
    
    public NetworkException(String message) {
        super(message);
    }
    
    public NetworkException(String message, Throwable cause) {
        super(message, cause);
    }
}
