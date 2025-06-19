package ChatV1;

/**
 * Main entry point for the chat server application
 */
public class ChatServerMain {
    public static void main(String[] args) {
        // Create and show the server GUI
        javax.swing.SwingUtilities.invokeLater(() -> new ChatServerGUI());
    }
}
