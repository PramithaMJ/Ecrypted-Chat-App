package Chat.common;

/**
 * Configuration class to centralize all application constants
 */
public class Config {
    // Network settings
    public static final int PORT = 12345;
    public static final String DEFAULT_SERVER_ADDRESS = "localhost";
    
    // Security settings
    public static final int RSA_KEY_SIZE = 2048;
    public static final int AES_KEY_SIZE = 256;
    public static final int IV_SIZE = 16;
    public static final String RSA_ALGORITHM = "RSA";
    public static final String AES_ALGORITHM = "AES";
    public static final String AES_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    
    // UI settings
    public static final int MAIN_WINDOW_WIDTH = 700;
    public static final int MAIN_WINDOW_HEIGHT = 600;
    public static final int SERVER_WINDOW_WIDTH = 900;
    public static final int SERVER_WINDOW_HEIGHT = 700;
    
    // Default values
    public static final String DEFAULT_CLIENT_NAME = "Guest";
}
