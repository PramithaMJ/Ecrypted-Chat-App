package Chat.common.exceptions;

/**
 * Exception thrown when there is an issue with cryptographic operations
 */
public class CryptoException extends Exception {
    private static final long serialVersionUID = 1L;
    
    public CryptoException(String message) {
        super(message);
    }
    
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
