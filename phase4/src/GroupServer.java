/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file. 
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;


public class GroupServer extends Server {

	public static final int SERVER_PORT = 5024;
	public UserList userList;
	public Hashtable<String, BigInteger> secrets;	//  <username, W = H(p)>
    
	public Key publicKey;
    public Key privateKey;

	private BigInteger g = new BigInteger("92356305589111923938577510282610817331995024932934095090679051297951462382210");	//g and p used to apply diffie hellman
	private BigInteger p = new BigInteger("88397245229545427575603639876844588157137584548492958882453140645069084311605");
	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}
	
	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}
	
	public void start() throws NoSuchProviderException, NoSuchAlgorithmException {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created 
		String userFile = "UserList.bin";
		//read RSAkey of group server
		String RSAFile= "RSAKeys.bin";
		
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		ObjectInputStream rsaStream;
		RSAObject rsaObject;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		
		//Open user file to get user list
		try
		{
			//System.out.println("Your Host addr: " + InetAddress.getLocalHost().getHostName()); 
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
			secrets = (Hashtable<String ,BigInteger>)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			System.out.print("Enter your password: ");
			String password = console.next();
			byte[] salt = "salt".getBytes();
			SRP6VerifierGenerator gen = new SRP6VerifierGenerator();
			gen.init(p, g, new SHA256Digest());
			BigInteger v = gen.generateVerifier(salt,username.getBytes(),password.getBytes()); //generate g^w mod p
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			secrets = new Hashtable<>();
			secrets.put(username,v);
			System.out.println("Administrator account is created. ");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		
		
		//Open RSA file to get public and private key
		try
		{
			//System.out.println("Your Host addr: " + InetAddress.getLocalHost().getHostName()); 
			FileInputStream fis = new FileInputStream(RSAFile);
			
			rsaStream = new ObjectInputStream(fis);
			rsaObject = (RSAObject)rsaStream.readObject();
			publicKey= rsaObject.returnPublic();
			privateKey= rsaObject.returnPrivate();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("RSA file doesn't find");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from RSA file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from RSA file");
			System.exit(-1);
		}
		
		
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
		
		//This block listens for connections and creates threads on new connections
		try
		{
			
			final ServerSocket serverSock = new ServerSocket(port);
			
			Socket sock = null;
			GroupThread thread = null;
			
			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}
	
}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;
	
	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			outStream.writeObject(my_gs.secrets);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;
	
	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
					outStream.writeObject(my_gs.secrets);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
