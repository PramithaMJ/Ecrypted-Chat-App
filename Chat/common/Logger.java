package Chat.common;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Centralized logging utility for both console and UI output
 */
public class Logger {
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("HH:mm:ss");
    
    private JTextArea logArea;
    private String prefix;
    private boolean consoleOutput;
    
    /**
     * Create a logger that outputs to both console and UI
     * @param logArea JTextArea for UI output, can be null for console-only
     * @param prefix Prefix to add to all log messages (e.g., "[SERVER]")
     * @param consoleOutput Whether to also output to the console
     */
    public Logger(JTextArea logArea, String prefix, boolean consoleOutput) {
        this.logArea = logArea;
        this.prefix = prefix != null ? prefix : "";
        this.consoleOutput = consoleOutput;
    }
    
    /**
     * Log an informational message
     */
    public void info(String message) {
        log(message, LogLevel.INFO);
    }
    
    /**
     * Log an error message
     */
    public void error(String message) {
        log(message, LogLevel.ERROR);
    }
    
    /**
     * Log a security-related message
     */
    public void security(String message) {
        log(message, LogLevel.SECURITY);
    }
    
    /**
     * Log a message with the specified level
     */
    private void log(String message, LogLevel level) {
        String timestamp = DATE_FORMAT.format(new Date());
        String formattedMessage = String.format("[%s] %s%s: %s", 
                timestamp, 
                prefix, 
                level.getTag(), 
                message);
        
        // Log to console if enabled
        if (consoleOutput) {
            if (level == LogLevel.ERROR) {
                System.err.println(formattedMessage);
            } else {
                System.out.println(formattedMessage);
            }
        }
        
        // Log to UI if available
        if (logArea != null) {
            final String finalMessage = formattedMessage + "\n";
            SwingUtilities.invokeLater(() -> {
                logArea.append(finalMessage);
                logArea.setCaretPosition(logArea.getDocument().getLength());
            });
        }
    }
    
    /**
     * Log levels with corresponding tags
     */
    public enum LogLevel {
        INFO(""),
        ERROR("[ERROR]"),
        SECURITY("[SECURITY]");
        
        private final String tag;
        
        LogLevel(String tag) {
            this.tag = tag;
        }
        
        public String getTag() {
            return tag;
        }
    }
}
