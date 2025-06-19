package ChatV1;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ChatServer {
   // Port number for the server
    private static final int PORT = 12345;
    
    // List to store all connected client handlers
    private static final List<ClientHandler> clients = new ArrayList<>();

    public static void main(String[] args) throws IOException {
        System.out.println("====Chat Server====");
        
        // Create a thread pool for handling clients
        ExecutorService pool = Executors.newCachedThreadPool();
        
        ServerSocket serverSocket = new ServerSocket(PORT);

        try {
            while (true) {
                // Listening for client connections
                System.out.println("Waiting for client connection...");
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress().getHostAddress());
                
                // Create a new client handler
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                clients.add(clientHandler);
                
                // Execute the client handler in the thread pool
                pool.execute(clientHandler);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            serverSocket.close();
            System.out.println("Server socket closed.");
            pool.shutdown();
        }
    }
    
    // Method to broadcast a message to all clients
    public static void broadcast(String message, ClientHandler sender) {
        synchronized (clients) {
            for (ClientHandler client : clients) {
                // Don't send message back to the sender
                if (client != sender) {
                    client.sendMessage(sender.getClientName() + ": " + message);
                }
            }
        }
    }
    
    // Method to remove a client from the list when they disconnect
    public static void removeClient(ClientHandler client) {
        synchronized (clients) {
            clients.remove(client);
        }
        System.out.println("Client disconnected: " + client.getClientName());
    } 
    
    // ClientHandler class to manage each client connection
    private static class ClientHandler implements Runnable {
        private Socket clientSocket;
        private PrintWriter out;
        private BufferedReader in;
        private String clientName;
        
        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
            this.clientName = "Client-" + socket.getInetAddress().getHostAddress();
        }
        
        public void sendMessage(String message) {
            out.println(message);
        }
        
        public String getClientName() {
            return clientName;
        }
        
        @Override
        public void run() {
            try {
                // Set up input and output streams
                out = new PrintWriter(clientSocket.getOutputStream(), true);
                in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                
                // Send welcome message
                out.println("Welcome to the Chat Server! Your default name is: " + clientName);
                out.println("Type 'NAME: your_name' to set your name.");
                
                // Process messages from this client
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    // Check if client is setting their name
                    if (inputLine.startsWith("NAME:")) {
                        String newName = inputLine.substring(5).trim();
                        if (!newName.isEmpty()) {
                            // Announce the name change
                            String announcement = "has changed their name to " + newName;
                            broadcast(announcement, this);
                            clientName = newName;
                            out.println("Name changed to: " + clientName);
                            continue;
                        }
                    }
                    
                    // Log the message on server console
                    System.out.println(clientName + ": " + inputLine);
                    
                    // Broadcast message to all other clients
                    broadcast(inputLine, this);
                }
            } catch (IOException e) {
                System.out.println("Error handling client: " + e.getMessage());
            } finally {
                try {
                    removeClient(this);
                    clientSocket.close();
                } catch (IOException e) {
                    System.out.println("Error closing client socket: " + e.getMessage());
                }
            }
        }
    } 
}
