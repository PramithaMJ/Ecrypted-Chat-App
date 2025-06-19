package Chat;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class ChatServer {
   // Port number for the server
    private static final int PORT = 12345;
    static String input = null;
    static String output = null;

    public static void main(String[] args) throws IOException {
        System.out.println("====Chat Server====");
        
        Scanner scanner = new Scanner(System.in);
        
        ServerSocket serverSocket = new ServerSocket(PORT);

        try {
            while (true) {
                // Listening for client connections
                System.out.println("Waiting for client connection...");
                Socket clienSocket = serverSocket.accept();
                System.out.println("Client connected: " + clienSocket.getInetAddress().getHostAddress());
                try {
                    // Create printwriter and buffered reader for client communication
                    PrintWriter out = new PrintWriter(clienSocket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(clienSocket.getInputStream()));
                    out.println("Welcome to the Chat Server!");

                    while (true) {
                        input = in.readLine();
                        System.out.println("Client: " + input);
                        output = scanner.nextLine();
                        out.println(output);
                    }
                } catch (Exception e) {
                    // TODO: handle exception
                } finally {
                    clienSocket.close();
                    System.out.println("Client disconnected.");
                }
            }
        } catch (Exception e) {
            // TODO: handle exception
        } finally {
            serverSocket.close();
            System.out.println("Server socket closed.");
            scanner.close();
        }
    } 
}
