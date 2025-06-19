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
    static String input = null;
    static String output = null;
    
    public static void main(String[] args) throws IOException, UnknownHostException {
        InetAddress ipAddress = InetAddress.getLocalHost();
        Scanner scanner = new Scanner(System.in);
        System.out.println("====Chat Client====");
        System.out.println("Connecting to server at " + ipAddress.getHostAddress() + ":" + PORT);

        // Create client socket
        Socket socket = new Socket(ipAddress, PORT);

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        while (true) {
            input = in.readLine();
            System.out.println("Server: " + input);
            System.out.print("Me: ");
            out.println(input);

        }
    }
}
