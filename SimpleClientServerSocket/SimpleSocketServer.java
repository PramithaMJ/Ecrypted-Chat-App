package SimpleClientServerSocket;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class SimpleSocketServer {
    // Port number for the server
    private static final int PORT = 12345;
    public static void main(String[] args) throws IOException {
        System.out.println("====Simple Socket Server====");
        // Creatting Servers socket
        ServerSocket serverSocket = new ServerSocket(PORT);
        try {
            while (true) {
                // Listening for client connections
                System.out.println("Waiting for client connection...");
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress().getHostAddress());
                try {
                    // Creaing printwriter and buffered reader for client communication
                    PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                    out.println("Hello from Simple Socket Server!");
                } finally {
                    // Closing client socket
                    clientSocket.close();
                    System.out.println("Client disconnected.");
                }
            }
        } finally {
            // Closing server socket
            serverSocket.close();
            System.out.println("Server socket closed.");
        }
    }
}