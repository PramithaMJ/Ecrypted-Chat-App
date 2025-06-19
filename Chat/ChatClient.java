package Chat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;

public class ChatClient {
    // Port number for the server
    private static final int PORT = 12345;
    
    public static void main(String[] args) {
        try {
            InetAddress serverAddress = InetAddress.getLocalHost();
            Scanner scanner = new Scanner(System.in);
            System.out.println("====Chat Client====");
            System.out.println("Connecting to server at " + serverAddress.getHostAddress() + ":" + PORT);

            // Create client socket and connect to the server
            Socket socket = new Socket(serverAddress, PORT);
            System.out.println("Connected to the chat server!");
            
            // Set up input and output streams
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            
            // Start a thread to handle incoming messages
            Thread messageReceiver = new Thread(() -> {
                try {
                    String message;
                    while ((message = in.readLine()) != null) {
                        System.out.println(message);
                    }
                } catch (IOException e) {
                    System.out.println("Disconnected from server.");
                }
            });
            messageReceiver.setDaemon(true); // Make this a daemon thread
            messageReceiver.start();
            
            // Main thread handles user input and sending messages
            System.out.println("Start typing messages (or 'exit' to quit):");
            String userInput;
            while (true) {
                userInput = scanner.nextLine();
                if (userInput.equalsIgnoreCase("exit")) {
                    break;
                }
                out.println(userInput);
            }
            
            // Clean up
            System.out.println("Disconnecting from server...");
            socket.close();
            scanner.close();
            
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
