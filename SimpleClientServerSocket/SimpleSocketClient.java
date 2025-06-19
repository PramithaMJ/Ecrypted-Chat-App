package SimpleClientServerSocket;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class SimpleSocketClient {
    // Port number for the server
    private static final int PORT = 12345;
    public static void main(String[] args) throws IOException , UnknownHostException{
        InetAddress ipAddress = InetAddress.getLocalHost();
        System.out.println("====Simple Socket Client====");
        System.out.println("Connecting to server at " + ipAddress.getHostAddress() + ":" + PORT);

        // Create client socket
        Socket socket = new Socket(ipAddress, PORT);

        // create buffered reader and printwriter for client communication
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        String serverMessage = in.readLine();
        System.out.println("Connection established successfully!");
        System.out.println("Message from server: " + serverMessage);


        System.exit(0);

    }
}
