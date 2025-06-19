package Chat.ui.client;

import Chat.common.Config;
import Chat.common.Logger;
import Chat.network.client.ChatClient;
import Chat.common.exceptions.NetworkException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * GUI implementation for the chat client
 */
public class ChatClientGUI extends JFrame {
    // Network components
    private ChatClient chatClient;
    
    // GUI components
    private JTextArea chatArea;
    private JTextArea securityInfoArea;
    private JTextField messageField;
    private JTextField nameField;
    private JButton sendButton;
    private JButton setNameButton;
    private JButton connectButton;
    private JButton disconnectButton;
    private JLabel statusLabel;
    private JLabel securityStatusLabel;
    
    // Logger
    private Logger chatLogger;
    private Logger securityLogger;
    
    public ChatClientGUI() {
        // Set up the window
        super("Secure Chat Client");
        setSize(Config.MAIN_WINDOW_WIDTH, Config.MAIN_WINDOW_HEIGHT);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Center on screen
        
        // Create loggers
        chatLogger = new Logger(null, "[CLIENT]", true);
        
        // Initialize client
        chatClient = new ChatClient(Config.DEFAULT_CLIENT_NAME, chatLogger);
        
        // Create components
        createComponents();
        
        // Layout components
        layoutComponents();
        
        // Add listeners
        addListeners();
        
        // Register callbacks for message handling
        registerClientCallbacks();
        
        // Show the window
        setVisible(true);
        
        // Add log message
        appendToChatArea("Welcome to the Secure Chat Client!");
        appendToChatArea("Click 'Connect' to connect to a chat server.");
    }
    
    private void createComponents() {
        chatArea = new JTextArea();
        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);
        
        securityInfoArea = new JTextArea();
        securityInfoArea.setEditable(false);
        securityInfoArea.setLineWrap(true);
        securityInfoArea.setWrapStyleWord(true);
        securityInfoArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        
        // Create security logger that outputs to the security info area
        securityLogger = new Logger(securityInfoArea, "", false);
        
        messageField = new JTextField(30);
        nameField = new JTextField(Config.DEFAULT_CLIENT_NAME, 15);
        
        sendButton = new JButton("Send");
        sendButton.setEnabled(false);
        
        setNameButton = new JButton("Set Name");
        setNameButton.setEnabled(false);
        
        connectButton = new JButton("Connect");
        disconnectButton = new JButton("Disconnect");
        disconnectButton.setEnabled(false);
        
        statusLabel = new JLabel("Not connected");
        statusLabel.setForeground(Color.RED);
        
        securityStatusLabel = new JLabel("Not Secure");
        securityStatusLabel.setForeground(Color.RED);
        securityStatusLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 12));
    }
    
    private void layoutComponents() {
        // Main content layout
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Split pane for chat and security info
        JScrollPane chatScrollPane = new JScrollPane(chatArea);
        chatScrollPane.setBorder(BorderFactory.createTitledBorder("Chat Messages"));
        
        JScrollPane securityScrollPane = new JScrollPane(securityInfoArea);
        securityScrollPane.setBorder(BorderFactory.createTitledBorder("Security Information"));
        
        JSplitPane splitPane = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            chatScrollPane,
            securityScrollPane
        );
        splitPane.setResizeWeight(0.7); // 70% to chat, 30% to security info
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // Control panel for connection management
        JPanel connectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        connectionPanel.add(connectButton);
        connectionPanel.add(disconnectButton);
        connectionPanel.add(statusLabel);
        connectionPanel.add(new JSeparator(SwingConstants.VERTICAL));
        connectionPanel.add(securityStatusLabel);
        
        // Name panel
        JPanel namePanel = new JPanel();
        namePanel.add(new JLabel("Your name:"));
        namePanel.add(nameField);
        namePanel.add(setNameButton);
        
        // Top panel combines connection and name panels
        JPanel topPanel = new JPanel(new GridLayout(2, 1));
        topPanel.add(connectionPanel);
        topPanel.add(namePanel);
        mainPanel.add(topPanel, BorderLayout.NORTH);
        
        // Message panel
        JPanel messagePanel = new JPanel();
        messagePanel.add(new JLabel("Message:"));
        messagePanel.add(messageField);
        messagePanel.add(sendButton);
        mainPanel.add(messagePanel, BorderLayout.SOUTH);
        
        // Add the main panel to the content pane
        getContentPane().add(mainPanel);
    }
    
    private void addListeners() {
        // Connect button
        connectButton.addActionListener(e -> connectToServer());
        
        // Disconnect button
        disconnectButton.addActionListener(e -> disconnectFromServer());
        
        // Send button
        sendButton.addActionListener(e -> sendMessage());
        
        // Set name button
        setNameButton.addActionListener(e -> setClientName());
        
        // Allow Enter key to send messages
        messageField.addActionListener(e -> sendMessage());
        
        // Window close event
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (chatClient != null) {
                    chatClient.shutdown();
                }
            }
        });
    }
    
    private void registerClientCallbacks() {
        // Set callbacks for message handling
        chatClient.setMessageCallback(this::appendToChatArea);
        chatClient.setSecurityCallback(this::appendToSecurityInfo);
        
        // Connection status callback
        chatClient.setConnectionStatusCallback(connected -> {
            SwingUtilities.invokeLater(() -> {
                connectButton.setEnabled(!connected);
                disconnectButton.setEnabled(connected);
                
                if (connected) {
                    statusLabel.setText("Connected to server");
                    statusLabel.setForeground(Color.GREEN);
                    setNameButton.setEnabled(true);
                    sendButton.setEnabled(true);
                } else {
                    statusLabel.setText("Not connected");
                    statusLabel.setForeground(Color.RED);
                    setNameButton.setEnabled(false);
                    sendButton.setEnabled(false);
                }
            });
        });
        
        // Security status callback
        chatClient.setSecurityStatusCallback(secure -> {
            SwingUtilities.invokeLater(() -> {
                if (secure) {
                    securityStatusLabel.setText("SECURE CONNECTION");
                    securityStatusLabel.setForeground(new Color(0, 130, 0));
                    securityStatusLabel.setFont(securityStatusLabel.getFont().deriveFont(Font.BOLD));
                } else {
                    securityStatusLabel.setText("NOT SECURE - MESSAGES UNENCRYPTED");
                    securityStatusLabel.setForeground(Color.RED);
                    securityStatusLabel.setFont(securityStatusLabel.getFont().deriveFont(Font.BOLD));
                }
            });
        });
    }
    
    private void connectToServer() {
        String serverAddress = JOptionPane.showInputDialog(
            this,
            "Enter server address:",
            Config.DEFAULT_SERVER_ADDRESS
        );
        
        if (serverAddress == null || serverAddress.trim().isEmpty()) {
            serverAddress = Config.DEFAULT_SERVER_ADDRESS;
        }
        
        try {
            chatClient.connect(serverAddress, Config.PORT);
        } catch (NetworkException e) {
            JOptionPane.showMessageDialog(
                this,
                "Failed to connect to server: " + e.getMessage(),
                "Connection Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }
    
    private void disconnectFromServer() {
        chatClient.disconnect();
    }
    
    private void sendMessage() {
        String message = messageField.getText().trim();
        if (message.isEmpty()) {
            return;
        }
        
        if (chatClient.sendMessage(message)) {
            // Only show [UNENCRYPTED] tag when it's actually not secure
            // When secure, don't show any tag as this is a secure chat client by default
            appendToChatArea("You: " + message + 
                           (!chatClient.isSecureConnection() ? " [UNENCRYPTED]" : ""));
        } else {
            appendToChatArea("Failed to send message");
        }
        
        // Clear the message field
        messageField.setText("");
    }
    
    private void setClientName() {
        String newName = nameField.getText().trim();
        if (newName.isEmpty()) {
            return;
        }
        
        if (chatClient.setName(newName)) {
            appendToChatArea("You changed your name to " + newName);
        } else {
            appendToChatArea("Failed to change name");
        }
    }
    
    private void appendToChatArea(String message) {
        SwingUtilities.invokeLater(() -> {
            chatArea.append(message + "\n");
            chatArea.setCaretPosition(chatArea.getDocument().getLength());
        });
    }
    
    private void appendToSecurityInfo(String message) {
        securityLogger.security(message);
    }
    
    public static void main(String[] args) {
        // Set the look and feel to the system default
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // Create and show the application on the EDT
        SwingUtilities.invokeLater(ChatClientGUI::new);
    }
}
