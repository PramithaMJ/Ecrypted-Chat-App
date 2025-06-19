package Chat.ui.server;

import Chat.common.Config;
import Chat.common.Logger;
import Chat.common.exceptions.NetworkException;
import Chat.network.server.ChatServer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * GUI implementation for the chat server
 */
public class ChatServerGUI extends JFrame {
    // Server component
    private ChatServer chatServer;
    
    // GUI components
    private JTextArea logArea;
    private JTextArea securityLogArea;
    private JButton startButton;
    private JButton stopButton;
    private JLabel statusLabel;
    private JLabel securityStatusLabel;
    private JList<String> clientList;
    private DefaultListModel<String> clientListModel;
    private JButton kickButton;
    private JButton broadcastButton;
    private JTextField broadcastField;
    
    // Loggers
    private Logger serverLogger;
    private Logger securityLogger;
    
    public ChatServerGUI() {
        // Set up the window
        super("Secure Chat Server");
        setSize(Config.SERVER_WINDOW_WIDTH, Config.SERVER_WINDOW_HEIGHT);
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
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        // Create server logger
        serverLogger = new Logger(logArea, "", false);
        
        securityLogArea = new JTextArea();
        securityLogArea.setEditable(false);
        securityLogArea.setLineWrap(true);
        securityLogArea.setWrapStyleWord(true);
        securityLogArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        securityLogArea.setForeground(new Color(0, 100, 0));
        
        // Create security logger
        securityLogger = new Logger(securityLogArea, "", false);
        
        // Server
        chatServer = new ChatServer(new Logger(logArea, "[SERVER]", true));
        
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
        
        // Set up callback to update client list
        chatServer.setClientListUpdatedCallback(this::updateClientList);
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
            chatServer.start(Config.PORT);
            
            // Update UI state
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            broadcastButton.setEnabled(true);
            statusLabel.setText("Server Online (Port " + Config.PORT + ")");
            statusLabel.setForeground(Color.GREEN);
            securityStatusLabel.setText("Security Active");
            securityStatusLabel.setForeground(new Color(0, 130, 0));
            
            log("Server started on port " + Config.PORT);
        } catch (NetworkException e) {
            JOptionPane.showMessageDialog(this,
                "Could not start server: " + e.getMessage(),
                "Server Error",
                JOptionPane.ERROR_MESSAGE);
        }
    }
    
    private void stopServer() {
        chatServer.stop();
        
        // Update UI state
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        broadcastButton.setEnabled(false);
        kickButton.setEnabled(false);
        statusLabel.setText("Server Offline");
        statusLabel.setForeground(Color.RED);
        securityStatusLabel.setText("Security Inactive");
        securityStatusLabel.setForeground(Color.ORANGE);
        
        // Clear client list
        clientListModel.clear();
        
        log("Server stopped");
    }
    
    private void kickSelectedClient() {
        int selectedIndex = clientList.getSelectedIndex();
        if (selectedIndex >= 0) {
            chatServer.kickClient(selectedIndex);
        }
    }
    
    private void broadcastToAll() {
        String message = broadcastField.getText().trim();
        if (message.isEmpty()) {
            return;
        }
        
        chatServer.broadcastFromServer(message);
        broadcastField.setText("");
    }
    
    private void updateClientList() {
        SwingUtilities.invokeLater(() -> {
            clientListModel.clear();
            for (String client : chatServer.getClientList()) {
                clientListModel.addElement(client);
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
    
    public static void main(String[] args) {
        // Set the look and feel to the system default
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // Create and show the application on the EDT
        SwingUtilities.invokeLater(ChatServerGUI::new);
    }
}
