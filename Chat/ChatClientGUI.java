package Chat;

import javax.swing.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

public class ChatClientGUI extends JFrame {
    // Network components
    private static final int PORT = 12345;
    private static final String SERVER_ADDRESS = "localhost"; // Change if server is elsewhere
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private String clientName = "Guest";
    
    // Cryptographic components
    private KeyPair keyPair;           // Client's RSA key pair
    private PublicKey serverPublicKey; // Server's public key
    private SecretKey sessionKey;      // AES session key for encryption
    private boolean isSecureConnection = false;

    // GUI components
    private JTextArea chatArea;
    private JTextArea securityInfoArea;  // Display cryptographic information
    private JTextField messageField;
    private JTextField nameField;
    private JButton sendButton;
    private JButton setNameButton;
    private JButton connectButton;
    private JButton disconnectButton;
    private JLabel statusLabel;
    private JLabel securityStatusLabel;  // Secure connection status

    public ChatClientGUI() {
        // Set up the window
        super("Chat Application");
        setSize(600, 500);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null); // Center on screen

        // Create components
        createComponents();

        // Layout components
        layoutComponents();

        // Add listeners
        addListeners();

        // Show the window
        setVisible(true);
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
        
        messageField = new JTextField(30);
        nameField = new JTextField("Guest", 15);
        
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
        
        // Make the window a bit larger for the additional components
        setSize(700, 600);
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
                disconnectFromServer();
            }
        });
    }

    private void connectToServer() {
        try {
            // Connect to the server
            socket = new Socket(SERVER_ADDRESS, PORT);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            // Update UI state
            connectButton.setEnabled(false);
            disconnectButton.setEnabled(true);
            statusLabel.setText("Connected to server");
            statusLabel.setForeground(Color.GREEN);
            
            // Add a welcome message
            appendToChatArea("Connected to the chat server!");
            appendToChatArea("Establishing secure connection...");
            
            // Set up cryptographic components
            try {
                setupSecureConnection();
            } catch (Exception ex) {
                appendToChatArea("WARNING: Could not establish secure connection: " + ex.getMessage());
                appendToSecurityInfo("Secure connection failed: " + ex.getMessage());
                ex.printStackTrace();
                
                // Enable UI even without security
                sendButton.setEnabled(true);
                setNameButton.setEnabled(true);
            }
            
            // Start a thread for receiving messages
            startMessageListener();
            
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, 
                "Could not connect to server: " + ex.getMessage(), 
                "Connection Error", 
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * Set up secure connection with the server using a hybrid cryptosystem
     */
    private void setupSecureConnection() throws Exception {
        // 1. Generate RSA key pair for this client
        appendToSecurityInfo("Generating RSA key pair...");
        keyPair = CryptoUtil.generateRSAKeyPair();
        appendToSecurityInfo("Client Public Key: " + CryptoUtil.publicKeyToString(keyPair.getPublic()).substring(0, 40) + "...");
        appendToSecurityInfo("Client Private Key: " + CryptoUtil.privateKeyToString(keyPair.getPrivate()).substring(0, 40) + "...");
        
        // 2. Send our public key to the server
        SecureMessage keyMessage = new SecureMessage(
            SecureMessage.MessageType.PUBLIC_KEY_EXCHANGE,
            clientName,
            CryptoUtil.publicKeyToString(keyPair.getPublic())
        );
        out.println(keyMessage.toTransmissionString());
        appendToSecurityInfo("Sent public key to server");
        
        // 3. Wait for the server's public key
        appendToChatArea("Waiting for server public key...");
        
        // The rest of the authentication flow will be handled by the message listener
    }
    
    /**
     * Append text to the security info area
     */
    private void appendToSecurityInfo(String message) {
        SwingUtilities.invokeLater(() -> {
            securityInfoArea.append(message + "\n");
            securityInfoArea.setCaretPosition(securityInfoArea.getDocument().getLength());
        });
    }

    private void disconnectFromServer() {
        if (socket != null && socket.isConnected()) {
            try {
                socket.close();
                appendToChatArea("Disconnected from server");
            } catch (IOException ex) {
                appendToChatArea("Error while disconnecting: " + ex.getMessage());
            }
        }
        
        // Update UI state
        connectButton.setEnabled(true);
        disconnectButton.setEnabled(false);
        sendButton.setEnabled(false);
        setNameButton.setEnabled(false);
        statusLabel.setText("Not connected");
        statusLabel.setForeground(Color.RED);
    }

    private void sendMessage() {
        String message = messageField.getText().trim();
        if (message.isEmpty() || out == null) {
            return;
        }
        
        try {
            // If we have a secure connection, encrypt the message
            if (isSecureConnection && sessionKey != null) {
                // Generate an IV for this message
                IvParameterSpec iv = CryptoUtil.generateIV();
                
                // Encrypt the message with AES
                String encryptedContent = CryptoUtil.encryptAES(message, sessionKey, iv);
                
                // Create a secure message
                SecureMessage secureMsg = new SecureMessage(
                    SecureMessage.MessageType.ENCRYPTED_MESSAGE,
                    clientName,
                    encryptedContent
                );
                
                // Sign the message with our private key for authentication
                String signature = CryptoUtil.sign(message, keyPair.getPrivate());
                secureMsg.setSignature(signature);
                
                // Send the encrypted message to the server
                out.println(secureMsg.toTransmissionString());
                
                // Log the original message in our chat area
                appendToChatArea("You: " + message + " [Encrypted]");
                appendToSecurityInfo("Sent encrypted message: " + message.substring(0, Math.min(20, message.length())) + 
                                   (message.length() > 20 ? "..." : ""));
            } else {
                // Send the message unencrypted if no secure connection
                out.println(message);
                appendToChatArea("You: " + message + " [UNENCRYPTED]");
                appendToSecurityInfo("WARNING: Message sent unencrypted");
            }
        } catch (Exception ex) {
            appendToChatArea("Error encrypting message: " + ex.getMessage());
            appendToSecurityInfo("Encryption error: " + ex.getMessage());
        }
        
        // Clear the message field
        messageField.setText("");
    }

    private void setClientName() {
        String newName = nameField.getText().trim();
        if (newName.isEmpty() || out == null) {
            return;
        }
        
        // Send the command to change name
        out.println("NAME: " + newName);
        clientName = newName;
    }

    private void startMessageListener() {
        // Thread to listen for incoming messages
        new Thread(() -> {
            try {
                String serverMessageStr;
                while ((serverMessageStr = in.readLine()) != null) {
                    // Check if this is a secure message
                    if (serverMessageStr.contains("|")) {
                        try {
                            // Parse the secure message
                            final SecureMessage secureMessage = SecureMessage.parseFromString(serverMessageStr);
                            
                            // Process based on message type
                            processSecureMessage(secureMessage);
                        } catch (Exception ex) {
                            final String errorMsg = "Error processing secure message: " + ex.getMessage();
                            SwingUtilities.invokeLater(() -> {
                                appendToChatArea(errorMsg);
                                appendToSecurityInfo(errorMsg);
                            });
                        }
                    } else {
                        // Regular, non-secure message
                        final String plainMessage = serverMessageStr;
                        SwingUtilities.invokeLater(() -> appendToChatArea(plainMessage));
                    }
                }
            } catch (IOException e) {
                if (!socket.isClosed()) {
                    SwingUtilities.invokeLater(() -> {
                        appendToChatArea("Lost connection to server: " + e.getMessage());
                        disconnectFromServer();
                    });
                }
            }
        }).start();
    }
    
    /**
     * Process different types of secure messages
     */
    private void processSecureMessage(final SecureMessage message) {
        SwingUtilities.invokeLater(() -> {
            try {
                switch (message.getType()) {
                    case PUBLIC_KEY_EXCHANGE:
                        // Received server's public key
                        appendToChatArea("Received server public key");
                        appendToSecurityInfo("Server Public Key: " + message.getContent().substring(0, 40) + "...");
                        
                        // Store the server's public key
                        serverPublicKey = CryptoUtil.stringToPublicKey(message.getContent());
                        
                        // Generate a symmetric AES key for the session
                        sessionKey = CryptoUtil.generateAESKey();
                        appendToSecurityInfo("Generated AES Session Key: " + 
                            CryptoUtil.secretKeyToString(sessionKey).substring(0, 40) + "...");
                        
                        // Encrypt the AES key with the server's public key and send it
                        String encryptedKey = CryptoUtil.encryptRSA(
                            sessionKey.getEncoded(), 
                            serverPublicKey
                        );
                        
                        SecureMessage keyExchangeMsg = new SecureMessage(
                            SecureMessage.MessageType.SYMMETRIC_KEY_EXCHANGE,
                            clientName,
                            encryptedKey
                        );
                        
                        // Sign the key with our private key for authentication
                        keyExchangeMsg.setSignature(CryptoUtil.sign(encryptedKey, keyPair.getPrivate()));
                        
                        // Send the encrypted key to the server
                        out.println(keyExchangeMsg.toTransmissionString());
                        appendToSecurityInfo("Sent encrypted AES key to server");
                        break;
                        
                    case AUTH_CHALLENGE:
                        // Server is challenging us to prove our identity
                        appendToChatArea("Received authentication challenge from server");
                        appendToSecurityInfo("Auth Challenge: " + message.getContent());
                        
                        // Sign the challenge with our private key
                        String signedResponse = CryptoUtil.sign(message.getContent(), keyPair.getPrivate());
                        
                        // Send the signed response
                        SecureMessage authResponse = new SecureMessage(
                            SecureMessage.MessageType.AUTH_RESPONSE,
                            clientName,
                            signedResponse
                        );
                        out.println(authResponse.toTransmissionString());
                        appendToSecurityInfo("Sent authentication response");
                        break;
                        
                    case AUTH_SUCCESS:
                        // Authentication successful
                        isSecureConnection = true;
                        appendToChatArea("Secure connection established with server!");
                        appendToSecurityInfo("Authentication successful - secure connection established");
                        
                        // Update UI to show secure connection
                        securityStatusLabel.setText("Secure Connection");
                        securityStatusLabel.setForeground(new Color(0, 130, 0));
                        
                        // Enable message sending
                        sendButton.setEnabled(true);
                        setNameButton.setEnabled(true);
                        break;
                        
                    case AUTH_FAILED:
                        appendToChatArea("Authentication failed!");
                        appendToSecurityInfo("WARNING: Authentication failed: " + message.getContent());
                        
                        // We'll still enable UI elements to allow communication, but warn about security
                        sendButton.setEnabled(true);
                        setNameButton.setEnabled(true);
                        break;
                        
                    case ENCRYPTED_MESSAGE:
                        if (sessionKey != null) {
                            // Decrypt the message
                            String decryptedMsg = CryptoUtil.decryptAES(message.getContent(), sessionKey);
                            
                            // Display the decrypted message
                            appendToChatArea(message.getSender() + ": " + decryptedMsg);
                            
                            // Verify signature if present
                            if (message.getSignature() != null && serverPublicKey != null) {
                                boolean verified = CryptoUtil.verify(
                                    decryptedMsg, 
                                    message.getSignature(), 
                                    serverPublicKey
                                );
                                if (verified) {
                                    appendToSecurityInfo("Received encrypted message from " + 
                                                       message.getSender() + " (signature verified)");
                                } else {
                                    appendToSecurityInfo("WARNING: Message signature verification failed!");
                                }
                            } else {
                                appendToSecurityInfo("Received encrypted message from " + 
                                                   message.getSender() + " (unsigned)");
                            }
                        } else {
                            appendToChatArea("ERROR: Received encrypted message but no session key available");
                            appendToSecurityInfo("ERROR: Cannot decrypt message, no session key");
                        }
                        break;
                        
                    default:
                        appendToChatArea(message.toDisplayString());
                        appendToSecurityInfo("Received message of type: " + message.getType());
                        break;
                }
            } catch (Exception ex) {
                appendToChatArea("Error processing message: " + ex.getMessage());
                appendToSecurityInfo("Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        });
    }

    private void appendToChatArea(String message) {
        chatArea.append(message + "\n");
        // Auto-scroll to bottom
        chatArea.setCaretPosition(chatArea.getDocument().getLength());
    }

    public static void main(String[] args) {
        // Create and show GUI on the EDT
        SwingUtilities.invokeLater(() -> new ChatClientGUI());
    }
}
