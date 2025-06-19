package Chat;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ChatServerGUI extends JFrame {
    // Network components
    private static final int PORT = 12345;
    private ServerSocket serverSocket;
    private ExecutorService pool;
    private boolean isRunning = false;
    private final List<ClientHandler> clients = new ArrayList<>();
    
    // GUI components
    private JTextArea logArea;
    private JButton startButton;
    private JButton stopButton;
    private JLabel statusLabel;
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
        
        startButton = new JButton("Start Server");
        stopButton = new JButton("Stop Server");
        stopButton.setEnabled(false);
        
        statusLabel = new JLabel("Server Offline");
        statusLabel.setForeground(Color.RED);
        statusLabel.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        
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
        JPanel controlPanel = new JPanel();
        controlPanel.add(startButton);
        controlPanel.add(stopButton);
        controlPanel.add(statusLabel);
        
        // Create header panel
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.add(controlPanel, BorderLayout.NORTH);
        
        // Log area with scrolling
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setBorder(BorderFactory.createTitledBorder("Server Log"));
        
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
            logScrollPane,
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
            // Create a thread pool for handling clients
            pool = Executors.newCachedThreadPool();
            
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
        
        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
            this.clientAddress = socket.getInetAddress().getHostAddress();
            this.clientName = "Client-" + clientAddress;
        }
        
        public void sendMessage(String message) {
            if (out != null) {
                out.println(message);
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
                
                // Process messages from this client
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    // Check if client is setting their name
                    if (inputLine.startsWith("NAME:")) {
                        String newName = inputLine.substring(5).trim();
                        if (!newName.isEmpty()) {
                            // Announce the name change
                            broadcast("has changed their name to " + newName, this);
                            log(clientName + " changed name to " + newName);
                            clientName = newName;
                            sendMessage("Name changed to: " + clientName);
                            updateClientList();
                            continue;
                        }
                    }
                    
                    // Log the message
                    log(clientName + ": " + inputLine);
                    
                    // Broadcast message to all other clients
                    broadcast(inputLine, this);
                }
            } catch (IOException e) {
                if (isRunning) {
                    log("Error handling client " + clientName + ": " + e.getMessage());
                }
            } finally {
                close();
            }
        }
    }

    public static void main(String[] args) {
        // Create and show GUI on the EDT
        SwingUtilities.invokeLater(() -> new ChatServerGUI());
    }
}
