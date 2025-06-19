package Chat;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;

public class ChatClientGUI extends JFrame {
    // Network components
    private static final int PORT = 12345;
    private static final String SERVER_ADDRESS = "localhost"; // Change if server is elsewhere
    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;
    private String clientName = "Guest";

    // GUI components
    private JTextArea chatArea;
    private JTextField messageField;
    private JTextField nameField;
    private JButton sendButton;
    private JButton setNameButton;
    private JButton connectButton;
    private JButton disconnectButton;
    private JLabel statusLabel;

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
    }

    private void layoutComponents() {
        // Main content layout
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Chat area with scrolling
        JScrollPane scrollPane = new JScrollPane(chatArea);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Control panel for connection management
        JPanel connectionPanel = new JPanel();
        connectionPanel.add(connectButton);
        connectionPanel.add(disconnectButton);
        connectionPanel.add(statusLabel);
        
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
            sendButton.setEnabled(true);
            setNameButton.setEnabled(true);
            statusLabel.setText("Connected to server");
            statusLabel.setForeground(Color.GREEN);
            
            // Add a welcome message
            appendToChatArea("Connected to the chat server!");
            
            // Start a thread for receiving messages
            startMessageListener();
            
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, 
                "Could not connect to server: " + ex.getMessage(), 
                "Connection Error", 
                JOptionPane.ERROR_MESSAGE);
        }
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
        
        // Send the message to the server
        out.println(message);
        
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
                String serverMessage;
                while ((serverMessage = in.readLine()) != null) {
                    // Use SwingUtilities to update UI from the EDT
                    final String messageToAppend = serverMessage;
                    SwingUtilities.invokeLater(() -> appendToChatArea(messageToAppend));
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
