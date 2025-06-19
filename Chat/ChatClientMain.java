package Chat;

import Chat.ui.client.ChatClientGUI;

/**
 * Main entry point for the chat client application
 */
public class ChatClientMain {
    public static void main(String[] args) {
        // Create and show the client GUI
        javax.swing.SwingUtilities.invokeLater(() -> new ChatClientGUI());
    }
}
