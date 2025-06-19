package ChatV1;

import javax.swing.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ChatServerGUI extends JFrame {
    // Network components
    private static final int PORT = 12345;
    private ServerSocket serverSocket;
    private ExecutorService pool;
    private boolean isRunning = false;
    private final java.util.List<ClientHandler> clients = new ArrayList<>();
    
    // Cryptographic components
    private KeyPair serverKeyPair;       // Server's RSA key pair
    private Map<String, PublicKey> clientPublicKeys = new HashMap<>();  // Store client public keys
    private Map<String, SecretKey> clientSessionKeys = new HashMap<>(); // Store session keys
    
    // GUI components
    private JTextArea logArea;
    private JTextArea securityLogArea;  // For security-related logs
    private JButton startButton;
    private JButton stopButton;
    private JLabel statusLabel;
    private JLabel securityStatusLabel; // Display security status
    private JList<String> clientList;
    private DefaultListModel<String> clientListModel;
    private JButton kickButton;
    private JButton broadcastButton;
    private JTextField broadcastField;

    public ChatServerGUI() {
        // Set up the window
        super("Chat Server Control Panel");
        setSize(800, 600);
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
        
        log("Server initialized. Click 'Start Server' to begin accepting connections.");
    }

    private void createComponents() {
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        securityLogArea = new JTextArea();
        securityLogArea.setEditable(false);
        securityLogArea.setLineWrap(true);
        securityLogArea.setWrapStyleWord(true);
        securityLogArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        securityLogArea.setForeground(new Color(0, 100, 0));
        
        startButton = new JButton("Start Server");
        stopButton = new JButton("Stop Server");
        stopButton.setEnabled(false);
        
        statusLabel = new JLabel("Server Offline");
        statusLabel.setForeground(Color.RED);
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        
        securityStatusLabel = new JLabel("Security Inactive");
        securityStatusLabel.setForeground(Color.ORANGE);
        securityStatusLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        
        clientListModel = new DefaultListModel<>();
        clientList = new JList<>(clientListModel);
        clientList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        kickButton = new JButton("Kick Client");
        kickButton.setEnabled(false);
        
        broadcastField = new JTextField(30);
        broadcastButton = new JButton("Broadcast");
        broadcastButton.setEnabled(false);
    }

    private void layoutComponents() {
        // Main content layout
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Server control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.add(startButton);
        controlPanel.add(stopButton);
        controlPanel.add(statusLabel);
        controlPanel.add(Box.createHorizontalStrut(20)); // Spacer
        controlPanel.add(securityStatusLabel);
        
        // Create header panel
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.add(controlPanel, BorderLayout.NORTH);
        
        // Log tabs - regular log and security log
        JTabbedPane logTabs = new JTabbedPane();
        
        // Regular log with scrolling
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        logTabs.addTab("Server Log", logScrollPane);
        
        // Security log with scrolling
        JScrollPane securityScrollPane = new JScrollPane(securityLogArea);
        securityScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        logTabs.addTab("Security Log", securityScrollPane);
        
        // Client panel
        JPanel clientPanel = new JPanel(new BorderLayout());
        JScrollPane clientScrollPane = new JScrollPane(clientList);
        clientScrollPane.setBorder(BorderFactory.createTitledBorder("Connected Clients"));
        clientPanel.add(clientScrollPane, BorderLayout.CENTER);
        
        // Client control buttons
        JPanel clientControlPanel = new JPanel(new FlowLayout());
        clientControlPanel.add(kickButton);
        clientPanel.add(clientControlPanel, BorderLayout.SOUTH);
        
        // Broadcast panel
        JPanel broadcastPanel = new JPanel();
        broadcastPanel.setBorder(BorderFactory.createTitledBorder("Broadcast Message"));
        broadcastPanel.add(new JLabel("Message:"));
        broadcastPanel.add(broadcastField);
        broadcastPanel.add(broadcastButton);
        
        // Create split pane for log and clients
        JSplitPane splitPane = new JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            logTabs,
            clientPanel
        );
        splitPane.setResizeWeight(0.7); // 70% to log, 30% to client list
        
        // Add components to main panel
        mainPanel.add(headerPanel, BorderLayout.NORTH);
        mainPanel.add(splitPane, BorderLayout.CENTER);
        mainPanel.add(broadcastPanel, BorderLayout.SOUTH);
        
        // Add the main panel to the content pane
        getContentPane().add(mainPanel);
        
        // Set a larger size for the server GUI
        setSize(900, 700);
    }

    private void addListeners() {
        // Start button
        startButton.addActionListener(e -> startServer());
        
        // Stop button
        stopButton.addActionListener(e -> stopServer());
        
        // Kick button
        kickButton.addActionListener(e -> kickSelectedClient());
        
        // Broadcast button
        broadcastButton.addActionListener(e -> broadcastToAll());
        
        // Client list selection
        clientList.addListSelectionListener(e -> {
            kickButton.setEnabled(!clientList.isSelectionEmpty());
        });
        
        // Window close event
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                stopServer();
            }
        });
    }

    private void startServer() {
        try {
            // Create a thread pool for handling clients
            pool = Executors.newCachedThreadPool();
            
            // Generate RSA key pair for the server
            try {
                serverKeyPair = CryptoUtil.generateRSAKeyPair();
                securityLog("Generated RSA key pair:");
                securityLog("Public Key: " + CryptoUtil.publicKeyToString(serverKeyPair.getPublic()).substring(0, 40) + "...");
                securityLog("Private Key: " + CryptoUtil.privateKeyToString(serverKeyPair.getPrivate()).substring(0, 40) + "...");
                
                // Update security status
                securityStatusLabel.setText("Security Active");
                securityStatusLabel.setForeground(new Color(0, 130, 0));
            } catch (Exception ex) {
                log("Warning: Could not initialize security components: " + ex.getMessage());
                securityLog("Security initialization failed: " + ex.getMessage());
                ex.printStackTrace();
            }
            
            // Create a server socket
            serverSocket = new ServerSocket(PORT);
            isRunning = true;
            
            // Update UI state
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            broadcastButton.setEnabled(true);
            statusLabel.setText("Server Online (Port " + PORT + ")");
            statusLabel.setForeground(Color.GREEN);
            
            log("Server started on port " + PORT);
            
            // Start a thread to accept client connections
            new Thread(this::acceptClients).start();
            
        } catch (IOException e) {
            log("Error starting server: " + e.getMessage());
            JOptionPane.showMessageDialog(this,
                "Could not start server: " + e.getMessage(),
                "Server Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    /**
     * Log a message to the security log area
     */
    private void securityLog(String message) {
        // Format timestamp
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        String timestamp = sdf.format(new Date());
        
        // Append to security log on EDT
        SwingUtilities.invokeLater(() -> {
            securityLogArea.append("[" + timestamp + "] " + message + "\n");
            securityLogArea.setCaretPosition(securityLogArea.getDocument().getLength());
        });
    }

    private void stopServer() {
        if (!isRunning) {
            return;
        }
        
        try {
            // Close all client connections
            synchronized (clients) {
                for (ClientHandler client : new ArrayList<>(clients)) {
                    client.close();
                }
                clients.clear();
            }
            
            // Close server socket
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            
            // Shutdown thread pool
            if (pool != null) {
                pool.shutdown();
            }
            
            // Update UI state
            isRunning = false;
            startButton.setEnabled(true);
            stopButton.setEnabled(false);
            broadcastButton.setEnabled(false);
            kickButton.setEnabled(false);
            statusLabel.setText("Server Offline");
            statusLabel.setForeground(Color.RED);
            
            // Clear client list
            SwingUtilities.invokeLater(() -> clientListModel.clear());
            
            log("Server stopped");
            
        } catch (IOException e) {
            log("Error stopping server: " + e.getMessage());
        }
    }

    private void acceptClients() {
        try {
            while (isRunning) {
                // Wait for a client connection
                Socket clientSocket = serverSocket.accept();
                
                // Create a new client handler
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                
                // Add to the client list
                synchronized (clients) {
                    clients.add(clientHandler);
                }
                
                // Start the client handler
                pool.execute(clientHandler);
                
                log("Client connected: " + clientSocket.getInetAddress().getHostAddress());
                updateClientList();
            }
        } catch (IOException e) {
            if (isRunning) {
                log("Error accepting client connection: " + e.getMessage());
            }
        }
    }

    private void kickSelectedClient() {
        int selectedIndex = clientList.getSelectedIndex();
        if (selectedIndex >= 0 && selectedIndex < clients.size()) {
            synchronized (clients) {
                ClientHandler client = clients.get(selectedIndex);
                client.sendMessage("*** You have been kicked from the server ***");
                client.close();
            }
        }
    }

    private void broadcastToAll() {
        String message = broadcastField.getText().trim();
        if (message.isEmpty()) {
            return;
        }
        
        broadcastSystemMessage("SERVER: " + message);
        broadcastField.setText("");
        log("Broadcast: " + message);
    }

    private void broadcastSystemMessage(String message) {
        synchronized (clients) {
            for (ClientHandler client : clients) {
                client.sendMessage(message);
            }
        }
    }

    // Method to broadcast a message to all clients
    private void broadcast(String message, ClientHandler sender) {
        synchronized (clients) {
            for (ClientHandler client : clients) {
                // Don't send message back to the sender
                if (client != sender) {
                    client.sendMessage(sender.getClientName() + ": " + message);
                }
            }
        }
    }

    private void updateClientList() {
        SwingUtilities.invokeLater(() -> {
            clientListModel.clear();
            synchronized (clients) {
                for (ClientHandler client : clients) {
                    clientListModel.addElement(client.getClientName() + " (" + 
                                             client.getClientAddress() + ")");
                }
            }
        });
    }

    private void log(String message) {
        // Format timestamp
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        String timestamp = sdf.format(new Date());
        
        // Append to log on EDT
        SwingUtilities.invokeLater(() -> {
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
    }

    // Remove a client from the list
    private void removeClient(ClientHandler client) {
        synchronized (clients) {
            clients.remove(client);
        }
        log("Client disconnected: " + client.getClientName());
        updateClientList();
    }

    // ClientHandler class to manage each client connection
    private class ClientHandler implements Runnable {
        private Socket clientSocket;
        private PrintWriter out;
        private BufferedReader in;
        private String clientName;
        private String clientAddress;
        private PublicKey clientPublicKey;      // Client's public key
        private SecretKey sessionKey;           // Shared AES session key
        private boolean secureConnectionEstablished = false;
        private String authenticationChallenge; // For two-way authentication
        
        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
            this.clientAddress = socket.getInetAddress().getHostAddress();
            this.clientName = "Client-" + clientAddress;
        }
        
        public void sendMessage(String message) {
            if (out != null) {
                // If we have a secure connection and a session key, encrypt the message
                if (secureConnectionEstablished && sessionKey != null && clientPublicKey != null) {
                    try {
                        // Generate IV for this message
                        IvParameterSpec iv = CryptoUtil.generateIV();
                        
                        // Encrypt the message with the session key
                        String encryptedContent = CryptoUtil.encryptAES(message, sessionKey, iv);
                        
                        // Create a secure message
                        SecureMessage secureMsg = new SecureMessage(
                            SecureMessage.MessageType.ENCRYPTED_MESSAGE,
                            "SERVER",
                            encryptedContent
                        );
                        
                        // Sign the message with the server's private key
                        secureMsg.setSignature(CryptoUtil.sign(message, serverKeyPair.getPrivate()));
                        
                        // Send the encrypted message
                        out.println(secureMsg.toTransmissionString());
                        securityLog("Sent encrypted message to " + clientName);
                    } catch (Exception ex) {
                        log("Error encrypting message for " + clientName + ": " + ex.getMessage());
                        // Fall back to unencrypted if encryption fails
                        out.println(message);
                    }
                } else {
                    // Send unencrypted if we don't have a secure connection
                    out.println(message);
                }
            }
        }
        
        public String getClientName() {
            return clientName;
        }
        
        public String getClientAddress() {
            return clientAddress;
        }
        
        public void close() {
            try {
                // Remove keys related to this client
                if (clientPublicKey != null) {
                    clientPublicKeys.remove(clientName);
                }
                if (sessionKey != null) {
                    clientSessionKeys.remove(clientName);
                }
                
                if (clientSocket != null && !clientSocket.isClosed()) {
                    clientSocket.close();
                }
                removeClient(this);
            } catch (IOException e) {
                log("Error closing client socket: " + e.getMessage());
            }
        }
        
        @Override
        public void run() {
            try {
                // Set up input and output streams
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                
                // Send welcome message
                sendMessage("Welcome to the Chat Server! Your default name is: " + clientName);
                sendMessage("Type 'NAME: your_name' to set your name.");
                
                // If we have server keys, tell the client we support secure chat
                if (serverKeyPair != null) {
                    log("Waiting for secure connection from client: " + clientName);
                }
                
                // Process messages from this client
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    // Check if this is a secure message
                    if (inputLine.contains("|")) {
                        try {
                            // Parse the secure message
                            SecureMessage secureMessage = SecureMessage.parseFromString(inputLine);
                            processSecureMessage(secureMessage);
                        } catch (Exception ex) {
                            log("Error processing secure message from " + clientName + ": " + ex.getMessage());
                            securityLog("Error: " + ex.getMessage());
                        }
                    }
                    // Regular message handling for unencrypted messages
                    else if (inputLine.startsWith("NAME:")) {
                        String newName = inputLine.substring(5).trim();
                        if (!newName.isEmpty()) {
                            // Announce the name change
                            broadcast("has changed their name to " + newName, this);
                            log(clientName + " changed name to " + newName);
                            clientName = newName;
                            sendMessage("Name changed to: " + clientName);
                            updateClientList();
                        }
                    }
                    else {
                        // Regular unencrypted message
                        log(clientName + ": " + inputLine);
                        broadcast(inputLine, this);
                    }
                }
            } catch (IOException e) {
                if (isRunning) {
                    log("Error handling client " + clientName + ": " + e.getMessage());
                }
            } finally {
                close();
            }
        }
        
        /**
         * Process different types of secure messages
         */
        private void processSecureMessage(SecureMessage message) {
            try {
                switch (message.getType()) {
                    case PUBLIC_KEY_EXCHANGE:
                        // Client is sending their public key
                        securityLog("Received public key from " + clientName);
                        
                        // Store the client's public key
                        clientPublicKey = CryptoUtil.stringToPublicKey(message.getContent());
                        clientPublicKeys.put(clientName, clientPublicKey);
                        
                        // Send our public key back
                        SecureMessage keyResponse = new SecureMessage(
                            SecureMessage.MessageType.PUBLIC_KEY_EXCHANGE,
                            "SERVER",
                            CryptoUtil.publicKeyToString(serverKeyPair.getPublic())
                        );
                        out.println(keyResponse.toTransmissionString());
                        securityLog("Sent server public key to " + clientName);
                        
                        // Send an authentication challenge
                        String challenge = generateAuthChallenge();
                        authenticationChallenge = challenge;
                        SecureMessage challengeMsg = new SecureMessage(
                            SecureMessage.MessageType.AUTH_CHALLENGE,
                            "SERVER",
                            challenge
                        );
                        out.println(challengeMsg.toTransmissionString());
                        securityLog("Sent authentication challenge to " + clientName);
                        break;
                        
                    case SYMMETRIC_KEY_EXCHANGE:
                        // Client is sending an encrypted AES key
                        securityLog("Received encrypted session key from " + clientName);
                        
                        // Decrypt the session key using our private key
                        byte[] decryptedKeyBytes = CryptoUtil.decryptRSA(message.getContent(), serverKeyPair.getPrivate());
                        sessionKey = new SecretKeySpec(decryptedKeyBytes, 0, decryptedKeyBytes.length, "AES");
                        clientSessionKeys.put(clientName, sessionKey);
                        
                        securityLog("Decrypted session key from " + clientName);
                        securityLog("Session key: " + CryptoUtil.secretKeyToString(sessionKey).substring(0, 40) + "...");
                        
                        // Verify the signature if provided
                        if (message.getSignature() != null && clientPublicKey != null) {
                            boolean verified = CryptoUtil.verify(
                                message.getContent(),
                                message.getSignature(),
                                clientPublicKey
                            );
                            
                            if (verified) {
                                securityLog("Signature on key verified for " + clientName);
                            } else {
                                securityLog("WARNING: Key signature verification failed for " + clientName);
                            }
                        }
                        break;
                        
                    case AUTH_RESPONSE:
                        // Client is responding to our authentication challenge
                        securityLog("Received authentication response from " + clientName);
                        
                        // Verify the response using the client's public key
                        if (authenticationChallenge != null && clientPublicKey != null) {
                            boolean verified = CryptoUtil.verify(
                                authenticationChallenge,
                                message.getContent(),
                                clientPublicKey
                            );
                            
                            if (verified) {
                                // Authentication successful
                                securityLog("Authentication successful for " + clientName);
                                secureConnectionEstablished = true;
                                
                                // Send authentication success message
                                SecureMessage successMsg = new SecureMessage(
                                    SecureMessage.MessageType.AUTH_SUCCESS,
                                    "SERVER",
                                    "Authentication successful, secure connection established"
                                );
                                out.println(successMsg.toTransmissionString());
                            } else {
                                // Authentication failed
                                securityLog("Authentication failed for " + clientName);
                                
                                SecureMessage failedMsg = new SecureMessage(
                                    SecureMessage.MessageType.AUTH_FAILED,
                                    "SERVER",
                                    "Authentication failed, connection will be insecure"
                                );
                                out.println(failedMsg.toTransmissionString());
                            }
                        }
                        break;
                        
                    case ENCRYPTED_MESSAGE:
                        // Received an encrypted message
                        if (sessionKey != null) {
                            // Decrypt the message using the session key
                            String decryptedMsg = CryptoUtil.decryptAES(message.getContent(), sessionKey);
                            
                            // Verify the signature if present
                            boolean verified = false;
                            if (message.getSignature() != null && clientPublicKey != null) {
                                verified = CryptoUtil.verify(
                                    decryptedMsg,
                                    message.getSignature(),
                                    clientPublicKey
                                );
                            }
                            
                            // Log the decrypted message
                            log(clientName + ": " + decryptedMsg + (verified ? " [Verified]" : ""));
                            
                            // Broadcast to all other clients
                            broadcast(decryptedMsg, this);
                            
                            securityLog("Received and decrypted message from " + clientName + 
                                      (verified ? " (signature verified)" : " (unsigned or unverified)"));
                        } else {
                            log("Error: Received encrypted message from " + clientName + " but no session key available");
                        }
                        break;
                        
                    default:
                        securityLog("Received unknown secure message type: " + message.getType() + " from " + clientName);
                        break;
                }
            } catch (Exception ex) {
                log("Error processing secure message: " + ex.getMessage());
                securityLog("Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
        
        /**
         * Generate a random challenge string for client authentication
         */
        private String generateAuthChallenge() {
            byte[] challengeBytes = new byte[32];
            new SecureRandom().nextBytes(challengeBytes);
            return Base64.getEncoder().encodeToString(challengeBytes);
        }
    }

    public static void main(String[] args) {
        // Create and show GUI on the EDT
        SwingUtilities.invokeLater(() -> new ChatServerGUI());
    }
}
