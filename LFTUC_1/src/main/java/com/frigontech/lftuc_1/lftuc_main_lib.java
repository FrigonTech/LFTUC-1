package com.frigontech.lftuc_1;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Telephony;
import android.util.Log;
import android.net.wifi.WifiManager;

import androidx.annotation.NonNull;

import java.net.*;
import java.nio.file.Files;
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
    public static String lftuc_getLocalIpv4Address () {
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
                    break;

                case "1":
                    //Status Code: 1 means server is offline (echoed while its going online)
                    if(!lftuc_currentServers.stream().anyMatch(server->server.ServerAddress.equals(PayloadParts.get(2)))){ //2-IP address
                        lftuc_currentServers.add(new LFTUCServers(
                                Integer.parseInt(PayloadParts.get(0)),
                                PayloadParts.get(1),
                                PayloadParts.get(2),
                                Integer.parseInt(PayloadParts.get(3)),
                                Integer.parseInt(PayloadParts.get(4))
                        ));
                    }
                    break;

                default:
                    //unknown address code
                    throw new LFTUCExceptions.PayloadParseFailureException();
            }

        }
        catch(Exception e){
            System.err.println(e.getMessage());
        }
    }

    //--------------------------------Start Listening to UDP Multicast and Receive Payload----------
    public static void startLFTUCMulticastListener(Context context, int port) {
        startLFTUCMulticastListener(context, "239.255.255.250", port);
    }
    public static void startLFTUCMulticastListener(Context context, String multicastGroup, int port) {
        WifiManager wifiManager = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        multicastLock = wifiManager.createMulticastLock("multicastLock");

        multicastThread = new Thread(() -> {
            try {
                
                multicastLock.acquire();

                multicastSocket = new MulticastSocket(port);
                multicastSocket.setReuseAddress(true);

                InetAddress group = InetAddress.getByName(multicastGroup);
                InetSocketAddress groupSocketAddress = new InetSocketAddress(group, port);

                
                NetworkInterface networkInterface = NetworkInterface.getByName("wlan0");

                if (networkInterface == null) {
                    
                    return;
                }

                multicastSocket.joinGroup(groupSocketAddress, networkInterface);
                

                byte[] buffer = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

                while (!Thread.currentThread().isInterrupted()) {
                    

                    if (multicastSocket.isClosed()) {
                        break;  // Exit if the socket is closed
                    }

                    multicastSocket.receive(packet);  // BLOCKING CALL

                    String message = new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8);

                    ParseLFTUCPayload(message);

                    packet.setLength(buffer.length); // Reset packet length
                }
            } catch (IOException e) {
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
                multicastThread.interrupt();  // Interrupt the thread, ensuring it stops waiting on receive
                multicastThread = null;
            }

            if (multicastSocket != null && !multicastSocket.isClosed()) {
                
                multicastSocket.close();  // Closing the socket unblocks the receive call
                multicastSocket = null;
            }

            if (multicastLock != null && multicastLock.isHeld()) {
                
                multicastLock.release();
            }
            lftuc_currentServers.clear();
        } catch (Exception e) {
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
        if (IPAddress.isBlank() || isEchoing) {
            Log.d("LFTUCEcho", "Echo not started: IP blank or already echoing.");
            return;
        }

        isEchoing = true;
        deadEchoPacketSent = false;

        multicastEchoThread = new Thread(() -> {
            MulticastSocket socket = null;
            try {
                InetAddress group = InetAddress.getByName(multicastGroup);
                socket = new MulticastSocket();
                socket.setReuseAddress(true);
                socket.setTimeToLive(32);

                NetworkInterface networkInterface = NetworkInterface.getByName("wlan0");
                if (networkInterface != null) {
                    socket.setNetworkInterface(networkInterface);
                }

                String lftuc_payload = AddressCode + "*" + DeviceName + "*" + IPAddress + "*" + port + "*" + OnlineStatus;
                byte[] data = lftuc_payload.getBytes(StandardCharsets.UTF_8);
                DatagramPacket packet = new DatagramPacket(data, data.length, group, port);

                while (isEchoing && !Thread.currentThread().isInterrupted()) {
                    socket.send(packet);
                    Log.d("LFTUCEcho", "Sent multicast packet: " + lftuc_payload);
                    Thread.sleep(2000);
                }

                // Send offline packet
                String declareOfflineEcho = AddressCode + "*" + DeviceName + "*" + IPAddress + "*" + port + "*0";
                data = declareOfflineEcho.getBytes(StandardCharsets.UTF_8);
                packet = new DatagramPacket(data, data.length, group, port);
                socket.send(packet);
                deadEchoPacketSent = true;
                Log.d("LFTUCEcho", "Sent dead echo packet.");
            } catch (IOException e) {
                Log.e("LFTUCEcho", "Multicast error: " + e.getMessage());
                lftuc_receivedMessages.add("Multicast error: " + e.getMessage());
            } catch (InterruptedException e) {
                Log.d("LFTUCEcho", "Multicast thread interrupted.");
            } finally {
                if (socket != null && !socket.isClosed()) {
                    socket.close();
                    Log.d("LFTUCEcho", "Multicast socket closed.");
                }
                isEchoing = false;
                deadEchoPacketSent = false;
            }
        });

        multicastEchoThread.start();
    }

    //-----------------------------------Stop LFTUC Echo--------------------------------------------
    public static void stopLFTUCMulticastEcho() {
        if (!isEchoing) {
            Log.d("LFTUCEcho", "Echo is not running.");
            return;
        }

        isEchoing = false;

        if (multicastEchoThread != null && multicastEchoThread.isAlive()) {
            multicastEchoThread.interrupt();
            try {
                multicastEchoThread.join(1000); // Timeout after 1 second
                Log.d("LFTUCEcho", "Multicast thread stopped.");
            } catch (InterruptedException e) {
                Log.e("LFTUCEcho", "Error joining multicast thread: " + e.getMessage());
            }
            multicastEchoThread = null;
        }

        lftuc_receivedMessages.add("Multicast echo stopped.");
    }
    //-------------------------------------START LFTUC Server---------------------------------------
    //-------------------------------------Server-Side Variables
    public static File lftuc_SharedDir = new File(Environment.getExternalStorageDirectory(), "/.LFTUC-Shared/Hosted");
    public static File lftuc_SharedFileDir = new File(Environment.getExternalStorageDirectory(), "/.LFTUC-Shared/Hosted");
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
        if (serverRunning.get()) {
            Log.d("LFTUCServer", "Server is already running.");
            return;
        }

        serverThread = new Thread(() -> {
            try {
                String ipv6Address = lftuc_getLinkLocalIPv6Address();
                if (ipv6Address == null) {
                    Log.e("LFTUCServer", "Failed to retrieve IPv6 address.");
                    serverRunning.set(false);
                    return;
                }

                InetAddress ipv6Addr = Inet6Address.getByName(ipv6Address);
                serverSocket = new ServerSocket();
                serverSocket.setReuseAddress(true);
                serverSocket.bind(new InetSocketAddress(ipv6Addr, 8080));

                File sharedDir = new File(context.getExternalFilesDir(null), ".LFTUC-Shared/Hosted");
                if (!sharedDir.exists()) {
                    sharedDir.mkdirs();
                    Log.d("LFTUCServer", "Created shared directory: " + sharedDir.getAbsolutePath());
                }

                lftuc_receivedMessages.add("Server started on: " + ipv6Address + ":8080");
                serverRunning.set(true);

                while (serverRunning.get() && !serverSocket.isClosed()) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        new Thread(() -> LFTUCHandleClient(clientSocket, rootAccess)).start();
                    } catch (IOException e) {
                        if (!serverRunning.get()) {
                            lftuc_receivedMessages.add("Server stopped, exiting accept loop.");
                            break;
                        }
                        lftuc_receivedMessages.add( "Error accepting connection: " + e.getMessage());
                    }
                }
            } catch (IOException e) {
                Log.e("LFTUCServer", "Server error: " + e.getMessage());
                lftuc_receivedMessages.add("Server error: " + e.getMessage());
            } finally {
                serverRunning.set(false);
                if (serverSocket != null && !serverSocket.isClosed()) {
                    try {
                        serverSocket.close();
                    } catch (IOException e) {
                        lftuc_receivedMessages.add("Error closing server socket: " + e.getMessage());
                    }
                }
                serverSocket = null;
                lftuc_receivedMessages.add("Server cleanup complete.");
            }
        });

        serverThread.start();
    }

    // -------------------------------- STOP LFTUC SERVER -----------------------------------
    public static void stopLFTUCServer() {
        Log.d("LFTUCServer", "Stopping server...");
        if (!serverRunning.get()) {
            Log.d("LFTUCServer", "Server is not running.");
            return;
        }

        serverRunning.set(false); // Signal server to stop

        try {
            // Close serverSocket first to unblock accept()
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
                serverSocket = null;
                Log.d("LFTUCServer", "Server socket closed.");
            }

            // Interrupt and join server thread
            if (serverThread != null && serverThread.isAlive()) {
                serverThread.interrupt();
                serverThread.join(2000); // Timeout after 2 seconds
                serverThread = null;
                Log.d("LFTUCServer", "Server thread stopped.");
            }

            lftuc_receivedMessages.add("Server stopped successfully");
        } catch (Exception e) {
            Log.e("LFTUCServer", "Error stopping server: " + e.getMessage());
            lftuc_receivedMessages.add("Error stopping server: " + e.getMessage());
        }
    }

    //------------------------------------Handle LFTUC Client---------------------------------------
    private static long calculateTotalSize(File dir) {
        long totalSize = 0;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    totalSize += calculateTotalSize(file);
                } else {
                    totalSize += file.length();
                }
            }
        }
        return totalSize;
    }
    private static void sendDirectory(File dir, String basePath, DataOutputStream dos) throws IOException {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    sendDirectory(file, basePath, dos); // Recurse
                } else {
                    FileInputStream fis = new FileInputStream(file);

                    String relativePath = file.getAbsolutePath().substring(basePath.length() + 1).replace("\\", "/");
                    dos.writeUTF(relativePath); // Send file path

                    long fileSize = file.length();
                    dos.writeLong(fileSize); // Send size of this file

                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        dos.write(buffer, 0, bytesRead); // Send file data
                    }

                    fis.close();
                }
            }
        }
    }

    private static void LFTUCHandleClient(Socket clientSocket, Boolean rootAccess) {
        try {

            InputStream inputStream = clientSocket.getInputStream();
            OutputStream outputStream = clientSocket.getOutputStream();

            BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(outputStream));

            String requestedPath = in.readLine();
            if (requestedPath == null) requestedPath = "";

            boolean isRequestingFileContent = requestedPath.contains("[req]");
            String newContentRequestedPath = "";

            //change path system according to client machine
            if (!requestedPath.isEmpty() && requestedPath.contains("\\")) //an escape for backslash; meaning '\
            {
                //for windows to android
                String[] processingsplices = requestedPath.split("\\\\");
                requestedPath = String.join("/", processingsplices); //converting from '\' to '/'
            }

            /*
                * get requested directory or file's local path on server
            */
            String[] requestSplices = requestedPath.split("/");
            List<String> requestSplicesStringList = new ArrayList<>(Arrays.asList(requestSplices));
            int requestLastIndex = requestSplicesStringList.size() - 1;
            String fixedFileName = "";
            if (isRequestingFileContent) {
                requestSplicesStringList.get(requestLastIndex).substring(6);//remove [FILE] from the requested file
                requestSplicesStringList.get(requestLastIndex).substring(0, requestSplicesStringList.get(requestLastIndex).length() - 5);//remove [req] from the requested file
            }else{
                requestSplicesStringList.get(requestLastIndex).substring(5);//remove [DIR] from the requested file
                requestSplicesStringList.get(requestLastIndex).substring(0, requestSplicesStringList.get(requestLastIndex).length() - 5);//remove [req] from the requested file
            }
            requestSplicesStringList.get(requestLastIndex).substring(0, requestSplicesStringList.get(requestLastIndex).length() - 5);//remove the [req] tag
            requestSplicesStringList.set(requestLastIndex, fixedFileName);
            newContentRequestedPath = String.join("/", requestSplicesStringList);


            File initialDir = rootAccess ? lftuc_RootDir : lftuc_SharedDir;
            File targetDir = new File(initialDir, requestedPath);


            if (targetDir.exists() && targetDir.isDirectory() && !isRequestingFileContent) {
                File[] files = targetDir.listFiles();
                for (File file : files) {
                    String fileEntry = file.isDirectory() ? "[DIR] " : "[FILE] ";
                    fileEntry += file.getName();
                    out.write(fileEntry + "\n");
                }
                out.write("LFTUC*FOLDEREND*\n");
                out.flush();
            } else if (isRequestingFileContent) {
                String fileRequestRootFolder = (rootAccess)? "/storage/emulated/0" : "/storage/emulated/0/.LFTUC-Shared/Hosted";
                File requestedFile = new File(fileRequestRootFolder, newContentRequestedPath);// hardcode the server files path (its default)
                DataOutputStream dos = new DataOutputStream(outputStream);
                if (requestedFile.isFile() && requestedFile.exists()) {
                    FileInputStream fis = new FileInputStream(requestedFile);

                    long fileSize = requestedFile.length();
                    dos.writeLong(fileSize); // ✅ This is what the client expects first!

                    byte[] buffer = new byte[4096];
                    int bytesRead;

                    while ((bytesRead = fis.read(buffer)) != -1) {
                        dos.write(buffer, 0, bytesRead);
                    }

                    fis.close();
                    dos.flush(); // Ensure all data is sent
                    dos.close();
                    out.flush();
                } else if(requestedFile.isDirectory() && requestedFile.exists()){
                    // Calculate total size of all files inside the folder
                    long totalSize = calculateTotalSize(requestedFile);
                    dos.writeLong(totalSize); // ✅ Send total size first!

                    // Now send all files
                    sendDirectory(requestedFile, requestedFile.getAbsolutePath(), dos);
                    dos.flush();
                }
                else{
                    dos.writeLong(-1L);  // Special flag: file doesn't exist
                    dos.flush(); // Ensure all data is sent
                    dos.close();
                }
            } else {

                out.write("LFTUC*ERROR* Invalid path\n");
                out.flush();
            }

            clientSocket.close();

        } catch (IOException e) {
        }
    }
    //-------------------------------Map file/folder to LFTUC server-------------------------------------
    //-----------------Mapping file/folder variables
    public static Boolean lftuc_needToReplaceObject = false;
    public static Boolean lftuc_getNeedToReplaceObject(){
        synchronized (lftuc_needToReplaceObject){
            return lftuc_needToReplaceObject;
        }
    }
    private static boolean copyFolderRecursively(File source, File dest) {
        if (source.isDirectory()) {
            if (!dest.exists() && !dest.mkdirs()) return false;
            File[] children = source.listFiles();
            if (children != null) {
                for (File child : children) {
                    if (!copyFolderRecursively(child, new File(dest, child.getName())))
                        return false;
                }
            }
        } else {
            try (InputStream in = new FileInputStream(source);
                 OutputStream out = new FileOutputStream(dest)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) > 0) {
                    out.write(buffer, 0, bytesRead);
                }
            } catch (IOException e) {
                return false;
            }
        }
        return true;
    }

    private static boolean deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    if (!deleteRecursively(child)) return false;
                }
            }
        }
        return file.delete();
    }
    public static Boolean moveFileObjectToLFTUCSharedDir(String[] filePath){
        Boolean Success = false;
        if(filePath.length<=1){
            Success = moveFileObjectToLFTUCSharedDir(filePath[0], false);
        }else{
            for (String file : filePath){
                Success = moveFileObjectToLFTUCSharedDir(file, false);
                if(Success!=true){
                    break;
                }
            }
        }

        return Success;
    }
    public static Boolean moveFileObjectToLFTUCSharedDir(String filePath, Boolean replaceObject){
        //the file path wheter file or folder should be passed as an absolute path/directory
        //target directory is lftuc_SharedDir //defined above
        if(!lftuc_SharedDir.exists()) {
            lftuc_SharedDir.mkdirs();
            lftuc_receivedMessages.add("created directory" + lftuc_SharedDir);
        } //make shared dir if it doesn't exist
        File sourceObject = new File(filePath);
        File destFolder = /*sourceObject.isDirectory()? */ lftuc_SharedDir /*: lftuc_SharedFileDir*/;
        File destObject = new File(destFolder, sourceObject.getName());

        if(!sourceObject.exists()){
            lftuc_receivedMessages.add("source file doesn't exist somehow");
            return false;
        }
        String sourceType = sourceObject.isDirectory()? "Folder" : "File";
        lftuc_receivedMessages.add("source type: " + sourceType);
        if(destObject.exists()){
            // manage repalce object for all rest of the files/folders or just do it for this one in
            //the look or single process
            lftuc_needToReplaceObject = true;
            lftuc_receivedMessages.add("need to replace file object: " + lftuc_needToReplaceObject);

            if(replaceObject) {
                destObject.delete();
                lftuc_receivedMessages.add("deleted destination file because it already existed");
            } else {
                lftuc_receivedMessages.add("no permission to delete destination object which had to be replaced");
                return false;
            }

            if (sourceObject.isFile()) {
                // Try to rename directly for a file
                try{
                    Files.copy(sourceObject.toPath(), destObject.toPath());
                    lftuc_receivedMessages.add("copying file (renaming it to new destination object: success: true");
                    return true;
                } catch (IOException e) {
                    lftuc_receivedMessages.add("exception while copying...: " + e);
                    return false;
                }

            } else {
                // For directories, copy contents recursively
                boolean movedDIR = copyFolderRecursively(sourceObject, destObject) && deleteRecursively(sourceObject);
                lftuc_receivedMessages.add("Copying contents recursively lmao. : " + movedDIR);
                return movedDIR;
            }
        }else{
            try{
                Files.copy(sourceObject.toPath(), destObject.toPath());
                lftuc_receivedMessages.add("copying file (renaming it to new destination object: success: true");
                return true;
            }catch(IOException e){
                lftuc_receivedMessages.add("failed copy file");
                return false;
            }

        }
    }
    //-------------------------------LFTUC Client-Side Requests-------------------------------------
    //-------------------------------Client-Side Variables
    public String lftuc_manipulatedPath = Environment.getExternalStorageDirectory().toString()+"/.LFTUC-Shared/Hosted";
    public static Thread clientThread;
    public static Socket clientSocket = new Socket();
    public File lftuc_CurrentPath() {
        return new File(lftuc_manipulatedPath);
    }
    public static volatile boolean isDownloadCancelled = false;
    public static void cancelFileDownload() {
        // Run cancel logic in a background thread
        new Thread(() -> {
            try {
                isDownloadCancelled = true;
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
                out.write("CANCEL FILE TRANSFER\n");
                out.flush();
                lftuc_receivedMessages.add("File Download Cancelled");
                
            } catch (IOException e) {
                lftuc_receivedMessages.add("File Download Not Cancelled");
            }
        }).start();
    }


    // Helper method to convert file size
    private static String convertFileSize(long fileSizeInBytes) {
        if (fileSizeInBytes < 1024) {
            return fileSizeInBytes + " B"; // Bytes
        } else if (fileSizeInBytes < 1024 * 1024) {
            return String.format("%.2f kB", fileSizeInBytes / 1024.0); // Kilobytes
        } else if (fileSizeInBytes < 1024 * 1024 * 1024) {
            return String.format("%.2f MB", fileSizeInBytes / (1024.0 * 1024)); // Megabytes
        } else if (fileSizeInBytes < 1024L * 1024 * 1024 * 1024) {
            return String.format("%.2f GB", fileSizeInBytes / (1024.0 * 1024 * 1024)); // Gigabytes
        } else {
            return String.format("%.2f TB", fileSizeInBytes / (1024.0 * 1024 * 1024 * 1024)); // Terabytes
        }
    }

    public interface LFTUCFolderCallback {
        void onResult(List<String> files);
        void onError(String errorMessage);
        void onProgress(int progress);  // Added progress callback
        void onGotFileSize(String fileSize); // in adjusted file size notation (b (bits) in its range, B (bytes) in its range, kb (kilobits) in its range, kB (kilo bytes) in its range, Gb (giga bits) for its range, GB (giga bytes) in its range)
        void onDownloadComplete(String downloadCompleteMessage);
    }
    public static void LFTUCRequestSharedFolder(String ServerAddress, int Port, String relativePath, LFTUCFolderCallback callback) {
        new Thread(() -> {
            List<String> filesInHere = new ArrayList<>();
            isDownloadCancelled = false;

//            if (lftuc_currentServers.isEmpty()) {
//                callback.onError("No Current Servers Found Yet!");
//                lftuc_receivedMessages.add("No Current Servers Found Yet!");
//                return;
//            } //intended implementation logic deprecated

            BufferedWriter out = null;
            BufferedReader in = null;
            DataInputStream dis = null;

            try {
                if (clientSocket == null || clientSocket.isClosed()) {
                    clientSocket = new Socket();
                }

                InetAddress ipv6Addr = Inet6Address.getByName(ServerAddress);
                clientSocket.connect(new InetSocketAddress(ipv6Addr, Port), 5000);

                out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
                out.write(relativePath + "\n");
                out.flush();

                dis = new DataInputStream(clientSocket.getInputStream());

                long fileSizeOrTotalSize = dis.readLong();

                if (fileSizeOrTotalSize == -1L) {
                    callback.onError("File/Folder doesn't exist on the server.");
                    lftuc_receivedMessages.add("File/Folder doesn't exist on server");
                    return;
                } else {
                    String formattedSize = convertFileSize(fileSizeOrTotalSize);
                    callback.onGotFileSize(formattedSize);
                }

                if (!relativePath.contains("[FILE]")) {
                    // Folder receiving mode
                    File baseSaveDir = new File(Environment.getExternalStorageDirectory(), ".LFTUC-Shared/LFTUC-Received");
                    if (!baseSaveDir.exists()) baseSaveDir.mkdirs();

                    long totalBytesReceived = 0;

                    while (totalBytesReceived < fileSizeOrTotalSize) {
                        String relativeFilePath = dis.readUTF(); // Read next file path
                        long singleFileSize = dis.readLong();    // Read its size

                        File outputFile = new File(baseSaveDir, relativeFilePath);
                        outputFile.getParentFile().mkdirs(); // Make sure folder exists

                        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                            byte[] buffer = new byte[4096];
                            long bytesRemaining = singleFileSize;
                            int bytesRead;

                            while (bytesRemaining > 0 && (bytesRead = dis.read(buffer, 0, (int) Math.min(buffer.length, bytesRemaining))) != -1) {
                                fos.write(buffer, 0, bytesRead);
                                bytesRemaining -= bytesRead;
                                totalBytesReceived += bytesRead;

                                int progress = (int) ((totalBytesReceived * 100) / fileSizeOrTotalSize);
                                callback.onProgress(progress);

                                if (isDownloadCancelled) {
                                    fos.close();
                                    outputFile.delete();
                                    callback.onError("Download cancelled.");
                                    return;
                                }
                            }
                        }

                        filesInHere.add(relativeFilePath); // Add the received file to result list
                    }

                    if (!isDownloadCancelled) {
                        callback.onResult(filesInHere);
                    }

                } else {
                    // Single file receiving mode
                    String fileName = relativePath.substring(relativePath.lastIndexOf('/') + 1);

                    File lftucDir = new File(Environment.getExternalStorageDirectory(), ".LFTUC-Shared/LFTUC-Received");
                    if (!lftucDir.exists()) lftucDir.mkdirs();
                    // Get free space in external storage
                    StatFs statFs = new StatFs(lftucDir.getAbsolutePath());
                    long availableBytes = (long) statFs.getAvailableBlocksLong() * statFs.getBlockSizeLong();
                    //check if the storage worth of downloading this file is even available in memory or not
                    // Compare and use formatted sizes in the error message
                    if (fileSizeOrTotalSize > availableBytes) {
                        String requiredSize = convertFileSize(fileSizeOrTotalSize);
                        String availableSize = convertFileSize(availableBytes);
                        callback.onError("Not enough space. Required: " + requiredSize + ", Available: " + availableSize + ".");
                        return;
                    }

                    String baseName = fileName;
                    String extension = "";
                    int dotIndex = fileName.lastIndexOf('.');
                    if (dotIndex > 0) {
                        baseName = fileName.substring(0, dotIndex);
                        extension = fileName.substring(dotIndex);
                    }

                    File targetFile = new File(lftucDir, baseName.substring(6) + extension);
                    int count = 1;
                    while (targetFile.exists()) {
                        targetFile = new File(lftucDir, "received_" + baseName + "(" + count + ")" + extension);
                        count++;
                    }

                    try (FileOutputStream fos = new FileOutputStream(targetFile)) {
                        byte[] buffer = new byte[4096];
                        long remaining = fileSizeOrTotalSize;
                        long totalRead = 0;
                        int read;

                        while ((read = dis.read(buffer, 0, (int) Math.min(buffer.length, remaining))) > 0) {
                            fos.write(buffer, 0, read);
                            remaining -= read;
                            totalRead += read;

                            int progress = (int) ((totalRead * 100) / fileSizeOrTotalSize);
                            callback.onProgress(progress);

                            if (isDownloadCancelled) {
                                fos.close();
                                targetFile.delete();
                                callback.onError("Download cancelled by user");
                                return;
                            }

                            if (remaining == 0) break;
                        }

                        if (!isDownloadCancelled && remaining == 0) {
                            callback.onDownloadComplete("File received and saved to: " + targetFile.getAbsolutePath());
                        }
                    } catch (IOException e) {
                        callback.onError("File write error: " + e.getMessage());
                    }
                }

            } catch (IOException e) {
                callback.onError("Request error: " + e.getMessage());

            } finally {
                try { if (out != null) out.close(); } catch (Exception ignored) {}
                try { if (in != null) in.close(); } catch (Exception ignored) {}
                try { if (dis != null) dis.close(); } catch (Exception ignored) {}
                try { if (clientSocket != null && !clientSocket.isClosed()) clientSocket.close(); } catch (Exception ignored) {}

                isDownloadCancelled = false;
            }
        }).start();
    }

    static {
        lftuc_receivedMessages.add("### STATIC TEST MSG ###");
        lftuc_currentServers.add(new LFTUCServers(1, "::1", "1234", 1, 1));
    }
    public static void printDebug() {
        System.out.println("MESSAGES: " + lftuc_receivedMessages.size() + " :: " + lftuc_receivedMessages);
        System.out.println("SERVERS: " + lftuc_currentServers.size() + " :: " + lftuc_currentServers);
    }
}
