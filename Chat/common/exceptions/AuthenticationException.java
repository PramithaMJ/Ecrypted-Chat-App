package Chat.common.exceptions;

/**
 * Exception thrown when there is an authentication issue
 */
public class AuthenticationException extends Exception {
    private static final long serialVersionUID = 1L;
    
    public AuthenticationException(String message) {
        super(message);
    }
    
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
