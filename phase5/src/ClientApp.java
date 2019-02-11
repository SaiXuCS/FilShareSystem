import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class ClientApp

{
	static BigInteger g = new BigInteger("92356305589111923938577510282610817331995024932934095090679051297951462382210");	//g and p used to apply diffie hellman
	static BigInteger p = new BigInteger("88397245229545427575603639876844588157137584548492958882453140645069084311605");
        static ArrayList<Entry> entries;
	public static void main(String [] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException, CryptoException

	{

		Security.addProvider(new BouncyCastleProvider());
		GroupClient gclient = new GroupClient();


		FileClient fclient = new FileClient();


		Scanner inScan = new Scanner(System.in);

		String hostname_group = args[0];
		String hostname_file= args[1];

		String username= "";
		String password="";
		String serverID = "";
		byte[] w;   //shared secret
		byte[] key;			//symmetric key generated through Diffie Hellman
		byte[] symmetricKey= new byte[16];
		int userflag = 0;

		
		if (args.length >= 4)	gclient.connect(hostname_group, Integer.parseInt(args[2]));
		else 	gclient.connect(hostname_group, Integer.parseInt(args[2]));

		UserToken token = null;

		

		while (userflag == 0)

		{

			System.out.print("Please enter your username:    ");
			username = inScan.nextLine();
			System.out.print("Please enter your password:    ");
			password = inScan.nextLine();
			System.out.print("What is the file server ID:    ");
			serverID = inScan.nextLine();
			/* exchange public keys */
			byte[] salt = "salt".getBytes();
			SRP6Client client = new SRP6Client();
			client.init(p,g,new SHA256Digest(),new SecureRandom());
			BigInteger clientPublicKey = client.generateClientCredentials(salt,username.getBytes(),password.getBytes());
			BigInteger serverPublicKey = gclient.exchangeKey(clientPublicKey,username); //send g^b mod p, receive g^s+g^w mod p
			if(serverPublicKey == null){
				System.out.println("User does not exist");
				System.exit(1);
			}
			key = client.calculateSecret(serverPublicKey).toByteArray();		// calculate symmetric key K
			for(int i= 0; i< 16; i++){
                               symmetricKey[i]= key[i];
                        }
			gclient.setClientGroupSymmetricKey(symmetricKey);
			boolean resultVerify= gclient.verifyGroupServer();
			if(!resultVerify){
				System.out.println("Group server may be a fake one");
				System.exit(1);
			}
			if(!gclient.passChallenge()){
				System.out.println("Key is compromised. Password is wrong or is received attack. ");
				System.exit(1);
			}

			token = gclient.getToken(username,serverID);
			gclient.shareHmacKey();
			if (token == null)

			{

				System.out.println("User Authentication Failed");

				System.out.println();

			}

			else

			{

				userflag = 1;

			}

		}


		if (args.length >=4)	fclient.connect(hostname_file, Integer.parseInt(args[3]));
		else	fclient.connect(hostname_file,FileServer.SERVER_PORT);
		int choice = 0;

		while (choice!= 12)

		{

                       
			//we need to send fclient token to verify that this token is sent from Group server
			if(!(fclient.vierfyToken(gclient.signedToken, token,gclient.tokenEncrypted,gclient.tokenKey,gclient.signedTokenKey,gclient.tokenIV))){
				System.out.println("File server verify token error");
				return;
			}
			if(!fclient.passChallenge()){
				System.out.println("File Server Key is compromised");
				System.exit(1);
			}
			fclient.shareHmacKey();
			System.out.println("\nWelcome back, " + username + ".");

			System.out.println("What would you like to do?");

			System.out.println("\t1. Create user");

			System.out.println("\t2. Delete user");

			System.out.println("\t3. Create group");

			System.out.println("\t4. Delete group");

			System.out.println("\t5. Add user to group");

			System.out.println("\t6. Delete user from group");

			System.out.println("\t7. List members of group");

			System.out.println("\t8. Upload a file");

			System.out.println("\t9. Download a file");

			System.out.println("\t10. Delete a file");

			System.out.println("\t11. List files");

			System.out.println("\t12. Disconnect");

		

			choice = inScan.nextInt();
			inScan.nextLine();

			if ((choice >= 13) || (choice <= 0))
			{

				System.out.println("Invalid choice.");
				choice= 0;
				continue;

			}

			

			

			if (choice == 1)

			{
				boolean created;
				System.out.print("What is the name of the new user? ");
				String newuser = inScan.nextLine();
				System.out.print("What is the password? ");
				String newpassword = inScan.nextLine();
				created = gclient.createUser(newuser, newpassword, token);

				if (!created)

				{

					System.out.println("User creation not successful.");
					continue;

				}

				else

				{

					System.out.println("User creation successful.\n\n\n\n");
					continue;

				}

			}

			

			if (choice == 2)

			{

				String olduser;

				boolean deleted;

				System.out.print("What is the username of the user to be deleted? ");

				olduser = inScan.nextLine();

				System.out.println();

				deleted = gclient.deleteUser(olduser, token);

				if (!deleted)

				{

					System.out.println("User deletion not successful.");
					continue;
				}

				else 

				{

					System.out.println("User deletion successful.");
					continue;
				}

			}

			

			if (choice == 3)

			{

				String newgroup;

				boolean gcreated;

				System.out.print("What is the name of the new group? ");

				newgroup = inScan.nextLine();

				System.out.println();

				gcreated = gclient.createGroup(newgroup, token);

				if (!gcreated)

				{

					System.out.println("Group creation not successful.");
					continue;
				}

				else

				{

					System.out.println("Group creation successful.");
					token = gclient.getToken(username,serverID);
					continue;
				}

			}

			

			if (choice == 4)

			{

				String oldgroup;

				boolean gdeleted;

				System.out.print("What is the name of the group to be deleted? ");

				oldgroup = inScan.nextLine();

				System.out.println();

				gdeleted = gclient.deleteGroup(oldgroup, token);

				if (!gdeleted)

				{

					System.out.println("Group deletion not successful.");
					continue;
				}

				else 

				{

					System.out.println("Group deletion successful.");
					token = gclient.getToken(username,serverID);
					continue;
				}

			}

			

			if (choice == 5)

			{

				String adduser;

				String addgroup;

				boolean added;

				System.out.print("What is the name of the user to be added? ");

				adduser = inScan.nextLine();

				System.out.println();

				System.out.print("What is the name of the group they will be added to? ");

				addgroup = inScan.nextLine();

				System.out.println();

				added = gclient.addUserToGroup(adduser, addgroup, token);

				if (!added)

				{

					System.out.println("User addition not successful.");
					continue;
				}

				else

				{

					System.out.println("User addition successful.");
					continue;
				}

			}

			

			if (choice == 6)

			{

				String deluser;

				String delgroup;

				boolean removed;

				System.out.print("What is the name of the user to be removed? ");

				deluser = inScan.nextLine();

				System.out.println();

				System.out.print("What is the name of the group they will be deleted from? ");

				delgroup = inScan.nextLine();

				System.out.println();

				removed = gclient.deleteUserFromGroup(deluser, delgroup, token);

				if (!removed)

				{

					System.out.println("User removal not successful.");
					continue;
				}

				else

				{

					System.out.println("User removal successful.");
					continue;
				}

			}

			

			if (choice == 7)

			{

				String listgroup;

				List<String> members;

				System.out.print("List the members from which group? ");

				listgroup = inScan.nextLine();

				System.out.println();

				members = gclient.listMembers(listgroup, token);
				if(members.size() == 0 ) System.out.println("You have no rights to see "+listgroup);
				else{
					for (String member : members) System.out.println(member);
				}
			}

			

			if (choice == 8)

			{

				String src;

				String dest;

				String upgroup;

				boolean uploaded;

				System.out.print("What is the name of the file? ");

				src = inScan.nextLine();

				System.out.println();

				System.out.print("What would you like the file to be called in the system? ");

				dest = inScan.nextLine();

				System.out.println();

				System.out.print("What group will this file be shared with? ");

				upgroup = inScan.nextLine();

				System.out.println();
                                entries= gclient.getGroupKeys(upgroup, token);
                                System.out.println("key in upload is "+ entries.get(0).aesKey.toString());
                                System.out.println("IV in upload is "+ new String(entries.get(0).iv, StandardCharsets.UTF_8));
				uploaded = fclient.upload(src, dest, upgroup, token);

				if (!uploaded)

				{

					System.out.println("File was not uploaded successfully.");
					continue;
				}

				else

				{

					System.out.println("File uploaded successfully.");
					continue;
				}

			}

			

			if (choice == 9)

			{

				String src;

				String dest;

				boolean downloaded;

				System.out.print("What file would you like to download? ");

				src = inScan.nextLine();

				System.out.println();

				System.out.print("What should the file be called on your local file system? ");

				dest = inScan.nextLine();

				System.out.println();
                                
                                String groupName= fclient.getGroupName(src, token);
                                System.out.println("group name "+groupName);
                                
                                entries= gclient.getGroupKeys(groupName, token);
                                if(entries== null){
                                    System.out.println("Not have right to this group file");
                                    continue;
                                }
                                System.out.println("key in download is "+ entries.get(0).aesKey.toString());
                                System.out.println("IV in download is "+ new String(entries.get(0).iv, StandardCharsets.UTF_8));
				downloaded = fclient.download(src, dest, token);

				if (!downloaded)

				{

					System.out.println("File was not downloaded successfully.");
					continue;
				}

				else

				{

					System.out.println("File downloaded successfully.");
					continue;
				}

			}

			

			if (choice == 10)

			{

				String file;

				boolean fdeleted;

				System.out.print("What file will be deleted? ");

				file = inScan.nextLine();

				System.out.println();

				fdeleted = fclient.delete(file, token);

				if (!fdeleted)

				{

					System.out.println("File was not deleted successfully.");
					continue;
				}

				else

				{

					System.out.println("File deleted successfully.");
					continue;
				}

			}

			

			if (choice == 11)
			{
				List<String> files = fclient.listFiles(token);
				for (String file : files) System.out.println(file);
			}

			

			if (choice == 12)

			{

				fclient.disconnect();

				gclient.disconnect();

				System.out.println("Disconnected. Good bye.");

			}

		

		}

	}
}
