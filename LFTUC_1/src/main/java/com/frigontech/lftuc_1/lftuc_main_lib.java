package com.frigontech.lftuc_1;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.provider.Telephony;
import android.util.Log;
import android.net.wifi.WifiManager;

import androidx.annotation.NonNull;

import java.net.*;
import java.security.spec.ECField;
import java.sql.Array;
import java.text.MessageFormat;
import java.util.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

public class lftuc_main_lib {

    //--------------------------------Get Local IPv4 Address of device------------------------------
    //1. Get all network interfaces
    //2. While Interfaces has 1 or more elements
    //---a. Iterate through all Network Interfaces
    //---b. Check for interfaces that are down and skip it
    //---c. Get InetAddress of that interface
    //---d. Skip loopback or IPv6 addresses
    //---e. Return the first valid IPv4 address (local)
    //3. Catch Exceptions (if any)
    public static String lftuc_getLocalIpv4Address() {
        try {
            // Get all network interfaces
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();

            while (networkInterfaces.hasMoreElements()) {
                NetworkInterface networkInterface = networkInterfaces.nextElement();

                // Skip loopback interfaces and interfaces that are down
                if (networkInterface.isLoopback() || !networkInterface.isUp()) {
                    continue;
                }

                // Check each address in the interface
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();

                    // Skip loopback addresses and IPv6 addresses
                    if (!address.isLoopbackAddress() && address.getHostAddress().indexOf(':') == -1) {
                        // Return the first valid IPv4 address
                        return address.getHostAddress();
                    }
                }
            }
        } catch (Exception e) {
            System.out.println("Exception in getting IPv4 address");
            e.fillInStackTrace();
        }
        return "null";
    }

    //--------------------------------Get Link Local IPv6 Address of device-------------------------
    //1. Try getting Wi-Fi network interfaces
    //2. Check if the interface is null
    //3. Get all Inet Address
    //4. While Wi-Fi interface has elements
    //---a. Iterate through all Inet Addresses
    //---b. Check if the addresses is instance of Inet6 Addresses and is a Link-Local Address
    //---c. Return hostAddresses of that Inet Address
    //3. Catch Exceptions (if any)
    public static String lftuc_getLinkLocalIPv6Address() {
        try {
            // Try to find an active network interface with a link-local IPv6 address
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!networkInterface.isUp() || networkInterface.isLoopback()) {
                    continue;
                }

                // ONLY use Wi-Fi interface (usually "wlan0")
                if (!networkInterface.getName().equalsIgnoreCase("wlan0")) continue;

                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();

                    // Check if it's a link-local IPv6 address
                    if (address instanceof Inet6Address && address.isLinkLocalAddress()) {
                        // Include the zone/scope ID (interface name)
                        String addressWithZone = address.getHostAddress();
                        if (!addressWithZone.contains("%")) {
                            addressWithZone += "%" + networkInterface.getName();
                        }
                        return addressWithZone;
                    }
                }
            }
        } catch (Exception e) {
            Log.e("LFTUC", "Exception in getting IPv6 address: " + e.getMessage(), e);
        }
        return null; // Return null, not "null" string
    }
    //---------------------------Log All Network Interfaces(for debugging)--------------------------
    public static void logAllNetworkInterfaces() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();

                lftuc_receivedMessages.add("NIC---- Interface: " + networkInterface.getName() + " ----");
                lftuc_receivedMessages.add("NIC Display Name: " + networkInterface.getDisplayName());
                lftuc_receivedMessages.add("NIC Is Up: " + networkInterface.isUp());
                lftuc_receivedMessages.add("NIC Is Loopback: " + networkInterface.isLoopback());
                lftuc_receivedMessages.add("NIC Supports Multicast: " + networkInterface.supportsMulticast());
                lftuc_receivedMessages.add("NIC Is Virtual: " + networkInterface.isVirtual());

                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    lftuc_receivedMessages.add("NIC Address: " + addr.getHostAddress());
                }
            }
        } catch (SocketException e) {
            lftuc_receivedMessages.add("NIC Error listing network interfaces: " + e.getMessage());
        }
    }
    //--------------------------------LISTENER VARIABLES--------------------------------------------
    private static Thread multicastThread;
    private static MulticastSocket multicastSocket;
    private static WifiManager.MulticastLock multicastLock;
    //------------Public synchronized message(response) list that Kotlin can access directly--------
    public static final List<String> lftuc_receivedMessages = Collections.synchronizedList(new ArrayList<>());
    public static List<String> lftuc_getReceivedMessages() {
        synchronized (lftuc_receivedMessages) {
            // Make sure to return an immutable copy for thread safety
            return Collections.unmodifiableList(new ArrayList<>(lftuc_receivedMessages));
        }
    }
    //---------------------------------------LFTUC Protocol Server List-----------------------------
    public static class LFTUCServers{
        public final Integer AddressCode;
        public final String ServerName;
        public final String ServerAddress;
        public final Integer ServerPort;
        public final Integer ServerStatus;

        public LFTUCServers(Integer AddressCode, String ServerName, String ServerAddress, Integer ServerPort, Integer ServerStatus){
            this.AddressCode=AddressCode;
            this.ServerName=ServerName;
            this.ServerAddress=ServerAddress;
            this.ServerPort=ServerPort;
            this.ServerStatus=ServerStatus;
        }

        @NonNull
        @Override
        public String toString(){
            return "lftuc://"+ServerName+"["+ServerAddress+"]:"+ServerPort+"/";
        }

        @Override
        public boolean equals(Object obj){
            if(this==obj) return true;
            if(obj==null || getClass() != obj.getClass()) return false;
            LFTUCServers other = (LFTUCServers) obj;
            return ServerAddress.equals(other.ServerAddress) &&
                    ServerPort.equals(other.ServerPort);
        }

        @Override
        public int hashCode(){
            return 31 * ServerAddress.hashCode() + ServerPort.hashCode();
        }
    }
    public static final List<LFTUCServers> lftuc_currentServers = Collections.synchronizedList(new ArrayList<>());
    public static List<LFTUCServers> lftuc_getCurrentServers() {
        synchronized (lftuc_currentServers) {
            return Collections.unmodifiableList(new ArrayList<>(lftuc_currentServers));
        }
    }
    //------------------------------------Parse LFTUC Payload---------------------------------------
    private static void ParseLFTUCPayload(String Payload){
        List<String> PayloadParts = Arrays.asList(Payload.split("\\*")); // we need 2 backslashes to tell regex to treat '*' literally
        lftuc_receivedMessages.add(PayloadParts.toString());
        try{
            // check is address code is something from the structure, need a better way in the future
            //check is the server is online and add server in the server list --"currentLFTUCServers"--
            switch (PayloadParts.get(4)){
                case "0":
                    //Status Code: 0 means server is offline (echoed while its going offline)
                    String IPAddress = PayloadParts.get(3);
                    synchronized (lftuc_currentServers){
                        lftuc_currentServers.removeIf(server-> server.ServerAddress.equals(IPAddress));
                    };
                    lftuc_receivedMessages.add("removed IP Address: "+IPAddress);
                    break;

                case "1":
                    //Status Code: 1 means server is offline (echoed while its going online)
                    if(!lftuc_currentServers.stream().anyMatch(server->server.ServerAddress.equals(PayloadParts.get(3)))){
                        lftuc_currentServers.add(new LFTUCServers(
                                Integer.parseInt(PayloadParts.get(0)),
                                PayloadParts.get(1),
                                PayloadParts.get(2),
                                Integer.parseInt(PayloadParts.get(3)),
                                Integer.parseInt(PayloadParts.get(4))
                        ));
                        lftuc_receivedMessages.add("added IP Address: "+PayloadParts.get(2));
                        Log.d("LFTUC", lftuc_currentServers.toString());
                    }
                    break;

                default:
                    //unknown address code
                    throw new LFTUCExceptions.PayloadParseFailureException();
            }

        }
        catch(Exception e){
            System.err.println(e.getMessage());
            lftuc_receivedMessages.add(e.getMessage());
            lftuc_receivedMessages.add(PayloadParts.get(4));
        }
    }

    //--------------------------------Start Listening to UDP Multicast and Receive Payload----------
    public static void startLFTUCMulticastListener(Context context, String multicastGroup, int port) {
        WifiManager wifiManager = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        multicastLock = wifiManager.createMulticastLock("multicastLock");

        multicastThread = new Thread(() -> {
            try {
                Log.d("MulticastReceiver", "Acquiring multicast lock...");
                multicastLock.acquire();
                lftuc_receivedMessages.add("Acquiring multicast lock...");

                Log.d("MulticastReceiver", "Creating MulticastSocket on port " + port);
                multicastSocket = new MulticastSocket(port);
                multicastSocket.setReuseAddress(true);
                lftuc_receivedMessages.add("Creating MulticastSocket on port " + port);

                InetAddress group = InetAddress.getByName(multicastGroup);
                InetSocketAddress groupSocketAddress = new InetSocketAddress(group, port);

                Log.d("MulticastReceiver", "Getting Network Interface...");
                lftuc_receivedMessages.add("Getting Network Interface...");
                NetworkInterface networkInterface = NetworkInterface.getByName("wlan0");

                if (networkInterface == null) {
                    Log.e("MulticastReceiver", "Network Interface wlan0 not found!");
                    lftuc_receivedMessages.add("Network Interface wlan0 not found!");
                    return;
                }

                Log.d("MulticastReceiver", "Joining multicast group " + multicastGroup);
                lftuc_receivedMessages.add("Joining multicast group " + multicastGroup);
                multicastSocket.joinGroup(groupSocketAddress, networkInterface);
                Log.d("MulticastReceiver", "Successfully joined group! Listening for packets...");
                lftuc_receivedMessages.add("Successfully joined group! Listening for packets...");

                byte[] buffer = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

                while (!Thread.currentThread().isInterrupted()) {
                    Log.d("MulticastReceiver", "Waiting for multicast packet...");
                    lftuc_receivedMessages.add("Waiting for multicast packet...");
                    multicastSocket.receive(packet);  // BLOCKING CALL

                    String message = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8);
                    Log.d("MulticastReceiver", "Multicast Received: " + message);
                    ParseLFTUCPayload(message);
                    lftuc_receivedMessages.add(message);

                    packet.setLength(buffer.length); // Reset packet length
                }
            } catch (IOException e) {
                Log.e("MulticastReceiver", "Multicast Error: " + e.getMessage(), e);
                lftuc_receivedMessages.add("Multicast Error: " + e.getMessage());
            } finally {
                stopLFTUCMulticastListener(); // Cleanup on exit
            }
        });

        multicastThread.start();
    }

    //------------------------------Function to stop the listener-----------------------------------
    public static void stopLFTUCMulticastListener() {
        try {
            if (multicastThread != null) {
                multicastThread.interrupt();  // Stop the thread
                multicastThread = null;
            }

            if (multicastSocket != null && !multicastSocket.isClosed()) {
                Log.d("MulticastReceiver", "Leaving multicast group...");
                lftuc_receivedMessages.add("Leaving multicast group...");
                multicastSocket.close();  // Closing the socket unblocks the receive call
                multicastSocket = null;
            }

            if (multicastLock != null && multicastLock.isHeld()) {
                Log.d("MulticastReceiver", "Releasing multicast lock...");
                lftuc_receivedMessages.add("Releasing multicast lock...");
                multicastLock.release();
            }
        } catch (Exception e) {
            Log.e("MulticastReceiver", "Error stopping multicast listener: " + e.getMessage(), e);
            lftuc_receivedMessages.add("Error stopping multicast listener: " + e.getMessage());
        }
    }

    //---------------------------------------ECHO VARIABLES-----------------------------------------
    private static Thread multicastEchoThread;
    private static boolean isEchoing = false;
    private static boolean deadEchoPacketSent = false;

    //------------------------------------Echo LFTUC Message----------------------------------------
    public static void startLFTUCMulticastEcho(int AddressCode, String DeviceName, String IPAddress, int port, int OnlineStatus){
        startLFTUCMulticastEcho(AddressCode, DeviceName, lftuc_getLinkLocalIPv6Address(), 8080, 1,"239.255.255.250");
    }
    public static void startLFTUCMulticastEcho(int AddressCode, String DeviceName, String IPAddress, int port, int OnlineStatus, String multicastGroup) {
        if(IPAddress.isBlank()){
            lftuc_receivedMessages.add("Invalid IP Address: "+IPAddress);
            return;
        }
        if (isEchoing) {
            lftuc_receivedMessages.add("MulticastEcho : Multicast echo is already running!");
            return;
        }
        isEchoing = true;
        deadEchoPacketSent = false;

        multicastEchoThread = new Thread(() -> {
            MulticastSocket socket = null;
            try {
                InetAddress group = InetAddress.getByName(multicastGroup);
                socket = new MulticastSocket();  // Use MulticastSocket instead of DatagramSocket
                socket.setReuseAddress(true);
                socket.setTimeToLive(32);  // Set TTL to allow broader propagation

                // Optionally bind to a specific network interface
                NetworkInterface networkInterface = NetworkInterface.getByName("wlan0");
                if (networkInterface != null) {
                    socket.setNetworkInterface(networkInterface);
                }

                DatagramPacket packet;
                int messageCounter = 0;
                String lftuc_payload = AddressCode+"*"+DeviceName+"*"+IPAddress+"*"+port+"*"+OnlineStatus;

                while (isEchoing) {
                    String numberedMessage = lftuc_payload + " - Message " + messageCounter++;
                    byte[] data = lftuc_payload.getBytes(StandardCharsets.UTF_8);
                    packet = new DatagramPacket(data, data.length, group, port);
                    Log.d("MulticastEcho:", "Sending multicast message: " + lftuc_payload);
                    lftuc_receivedMessages.add("MulticastEcho: Sending multicast message: "+numberedMessage);
                    socket.send(packet);
                    Thread.sleep(2000);  // Wait 2 seconds before sending again
                }

                String declareOfflineEcho = AddressCode+"*"+DeviceName+"*"+IPAddress+"*"+port+"*"+0;
                byte[] data = declareOfflineEcho.getBytes(StandardCharsets.UTF_8);
                packet = new DatagramPacket(data, data.length, group, port);
                socket.send(packet);
                deadEchoPacketSent = true;
            } catch (IOException e) {
                lftuc_receivedMessages.add("MulticastEcho: Error in multicast echo: " + e.getMessage());
                Log.e("MulticastEcho", "Error: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                lftuc_receivedMessages.add("MulticastEcho: Thread interrupted");
                Log.d("MulticastEcho", "Thread interrupted");
                isEchoing = false;
            } finally {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                }
            }
        });

        multicastEchoThread.start();
    }

    //-----------------------------------Stop LFTUC Echo--------------------------------------------
    public static void stopLFTUCMulticastEcho() {
        isEchoing = false;
        while(!deadEchoPacketSent){
            if(deadEchoPacketSent){
                if (multicastEchoThread != null) {
                    multicastEchoThread.interrupt();
                    multicastEchoThread = null;
                }
            }
        }
        lftuc_receivedMessages.add("MulticastEcho : Multicast echo stopped.");
    }
    //-------------------------------------START LFTUC Server---------------------------------------
    //-------------------------------------Server-Side Variables
    public static File lftuc_SharedDir = new File(Environment.getExternalStorageDirectory(), ".LFTUC-Shared");
    public static File lftuc_RootDir = Environment.getExternalStorageDirectory();
    public static ServerSocket serverSocket;
    public static AtomicBoolean serverRunning = new AtomicBoolean(false);
    public static Boolean lftuc_getServerRunning(){
        synchronized (serverRunning){
            return serverRunning.get();
        }
    }
    public static Thread serverThread;
    public static void startLFTUCServer(Context context) {
        startLFTUCServer(context, false);
    }
    public static void startLFTUCServer(Context context, Boolean rootAccess) {
        if(serverRunning.get()){
            lftuc_receivedMessages.add("LFTUC SERVER IS ALREADY RUNNING!");
            Log.d("Server:", "already running.");
            return;
        }
        serverThread = new Thread(() -> {
            try {
                String ipv6Address = lftuc_getLinkLocalIPv6Address();
                if (ipv6Address == null) {
                    lftuc_receivedMessages.add("Error: Could not find a valid IPv6 link-local address");
                    Log.d("Server:", "couldn't fina a valid ipv6 address.");
                    serverRunning.set(false);
                    return;
                }

                // Use IPv6 link-local address with zone (interface) specified
                InetAddress ipv6Addr = Inet6Address.getByName(ipv6Address);

                serverSocket = new ServerSocket();
                // Bind to the IPv6 address and port 8080
                serverSocket.bind(new InetSocketAddress(ipv6Addr, 8080));
                lftuc_receivedMessages.add("LFTUC SERVER STARTED\nlftuc://" + ipv6Addr.getHostAddress() + ":8080");
                File sharedDir = new File(Environment.getExternalStorageDirectory(), ".LFTUC-Shared");
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
                    lftuc_receivedMessages.add("no write permission");
                    return;
                }
                serverRunning.set(true);
                Log.d("Server:", "serverRunning.get() = true");

                if (!sharedDir.exists()) {
                    sharedDir.mkdirs(); // use mkdirs() for nested paths
                    lftuc_receivedMessages.add("Created directory: " + sharedDir.getAbsolutePath());
                }else{
                    lftuc_receivedMessages.add("Directory already exists: " + sharedDir.getAbsolutePath());
                }

                // Server is now live, serve the file to any connecting client
                while (serverRunning.get()) {
                    Socket clientSocket = serverSocket.accept();
                    new Thread(() -> LFTUCHandleClient(clientSocket, rootAccess)).start();
                }

            } catch (IOException e) {
                lftuc_receivedMessages.add("Server error: " + e.getMessage());
                serverRunning.set(false);
                Log.d("Server:", "serverRunning.get() = false");
            }
        });

        serverThread.start();
    }
    //------------------------------------STOP LFTUC Server-----------------------------------------
    public static void stopLFTUCServer(){
        try{
            if(serverSocket != null && !serverSocket.isClosed()){
                serverSocket.close();
                lftuc_receivedMessages.add("LFTUC SERVER STOPPED!");
                serverRunning.set(false);
                Log.d("Server:", "serverRunning.get() = false");
            }
        }catch(IOException ignored) {} // the try block almost can't fail so ignore this.
    }
    //------------------------------------Handle LFTUC Client---------------------------------------
    private static void LFTUCHandleClient(Socket clientSocket, Boolean rootAccess) {
        try (
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()))
        ) {
            lftuc_receivedMessages.add("Client connected from " + clientSocket.getInetAddress());

            // Read the requested relative path from client
            String requestedPath = in.readLine(); // could be "" or "SubFolder"
            if (requestedPath == null) requestedPath = "";

            // Build the full path under shared directory
            File initialDir = (rootAccess)? lftuc_RootDir : lftuc_SharedDir;
            File targetDir = new File(initialDir, requestedPath);
            lftuc_receivedMessages.add("Requested folder: " + targetDir.getAbsolutePath());

            if (targetDir.exists() && targetDir.isDirectory()) {
                File[] files = targetDir.listFiles();
                lftuc_receivedMessages.add("LFTUC*FOLDERSTART*");
                if (files != null) {
                    for (File file : files) {
                        lftuc_receivedMessages.add((file.isDirectory() ? "[DIR] " : "[FILE] ") + file.getName());
                    }
                }
                lftuc_receivedMessages.add("LFTUC*FOLDEREND*");
            } else {
                lftuc_receivedMessages.add("LFTUC*ERROR* Invalid path\n");
            }

            out.flush();
            clientSocket.close();

        } catch (IOException e) {
            lftuc_receivedMessages.add("Client error: " + e.getMessage());
        }
    }
    //-------------------------------Map folder to LFTUC server-------------------------------------
    //-----------------Mapping folder variables
    public static Boolean lftuc_needToReplaceObject = false;
    public static Boolean lftuc_getNeedToReplaceObject(){
        synchronized (lftuc_needToReplaceObject){
            return lftuc_needToReplaceObject;
        }
    }
    public static Boolean moveFileObjectToLFTUCSharedDir(String filePath){
        return moveFileObjectToLFTUCSharedDir(filePath, false);
    }
    public static Boolean moveFileObjectToLFTUCSharedDir(String filePath, Boolean replaceObject){
        //the file path wheter file or folder should be passed as an absolute path/directory
        //target directory is lftuc_SharedDir //defined above
        if(!lftuc_SharedDir.exists()) lftuc_SharedDir.mkdirs(); //make shared dir if it doesn't exist
        File sourceObject = new File(filePath);
        File destObject = new File(lftuc_SharedDir, sourceObject.getName());

        if(!sourceObject.exists()){
            lftuc_receivedMessages.add("source file or folder doesn't exist");
            return false;
        }
        String sourceType = sourceObject.isDirectory()? "Folder" : "File";
        if(destObject.exists()){
            // manage repalce object for all rest of the files/folders or just do it for this one in
            //the look or single process
            lftuc_needToReplaceObject = true;

            if(replaceObject) destObject.delete(); else return false;

            if(sourceObject.renameTo(destObject)) {
                lftuc_receivedMessages.add(sourceType + " moved...");
                return true;
            } else {
                lftuc_receivedMessages.add("can't move " + sourceType + "...");
                return false;
            }
        }else{
            if(sourceObject.renameTo(destObject)) {
                lftuc_receivedMessages.add(sourceType + " moved...");
                return true;
            } else {
                lftuc_receivedMessages.add("can't move " + sourceType + "...");
                return false;
            }
        }
    }
    //-------------------------------LFTUC Client-Side Requests-------------------------------------
    //-------------------------------Client-Side Variables
    public String lftuc_manipulatedPath = Environment.getExternalStorageDirectory().toString()+"/.LFTUC-Shared";
    public static Thread clientThread;
    public File lftuc_CurrentPath() {
        return new File(lftuc_manipulatedPath);
    }

    public interface LFTUCFolderCallback {
        void onResult(List<String> files);
        void onError(String errorMessage);
    }

    public static void LFTUCRequestSharedFolder(String ServerAddress, int Port, String relativePath, LFTUCFolderCallback callback) {
        new Thread(() -> {
            List<String> filesInHere = new ArrayList<>();

            if (lftuc_currentServers.size() > 0) {
                try {
                    InetAddress ipv6Addr = Inet6Address.getByName(ServerAddress);
                    Socket socket = new Socket();
                    socket.connect(new InetSocketAddress(ipv6Addr, Port), 5000);

                    BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                    out.write(relativePath + "\n");
                    out.flush();

                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    String response;
                    while ((response = in.readLine()) != null) {
                        lftuc_receivedMessages.add("Received: " + response);
                        if (response.startsWith("LFTUC*FOLDEREND*") || response.startsWith("LFTUC*ERROR*")) {
                            break;
                        } else {
                            filesInHere.add(response);
                        }
                    }

                    in.close();
                    out.close();
                    socket.close();

                    callback.onResult(filesInHere); // ✅ callback when done

                } catch (IOException e) {
                    callback.onError("Request error: " + e.getMessage());
                }
            } else {
                callback.onError("No Current Servers Found Yet!");
            }
        }).start();
    }
}
