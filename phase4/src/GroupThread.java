/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.Thread;
import java.math.BigInteger;
import java.net.Socket;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;
	BigInteger g = new BigInteger("92356305589111923938577510282610817331995024932934095090679051297951462382210");	//g and p used to apply diffie hellman
	BigInteger p = new BigInteger("88397245229545427575603639876844588157137584548492958882453140645069084311605");
	byte[] key;	//symmetric key obtained from Deff-hellman algorithm
	byte[] symmetricKey= new byte[16];
	byte[] hmacKey;
	Key publicKey;
	Key privateKey;
	Cipher enc;
	Cipher dec;
	int sequence = 0;
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		Security.addProvider(new BouncyCastleProvider());
		socket = _socket;
		my_gs = _gs;
		publicKey= _gs.publicKey;
		privateKey= _gs.privateKey;
	}
	//use group private key to signed token
	public byte[] signature(byte[] data)throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException{
        Cipher cipher= Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] signature = cipher.doFinal(data);
        return signature;
    }
	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;


				if(message.getMessage().equals("VerifyGroup")){
					byte[] encrypt= (byte[])message.getObjContents().get(0);
					Cipher cipher= Cipher.getInstance("RSA");
                                        cipher.init(Cipher.DECRYPT_MODE,privateKey);
                                        byte[] challenge= cipher.doFinal(encrypt);

                                        Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                        SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
					enc.init(Cipher.ENCRYPT_MODE, secretKeySpec);
					byte[] encryptedChallenge= enc.doFinal(challenge);
					byte[] iv= enc.getIV();
					byte[] signed= signature(encryptedChallenge);
					Envelope returnResponse= new Envelope("OK");


					returnResponse.addObject(signed);
					returnResponse.addObject(iv);
					output.writeObject(returnResponse);
				}
				else if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					String serverID = (String)message.getObjContents().get(1); //Get the server id
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username,serverID); //Create a token
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");

						// serialize the envelop object which contain token to string
						byte[] serializedObject;
						//int hashObject;
						byte[] hashObject;
						MessageDigest digest= MessageDigest.getInstance("SHA-256");
						try {
							//we serialize token and signed it use group public key
						    ByteArrayOutputStream bo = new ByteArrayOutputStream();
							ObjectOutputStream so = new ObjectOutputStream(bo);
							so.writeObject(yourToken);
							so.flush();
							serializedObject = bo.toByteArray();
							hashObject= digest.digest(serializedObject);
							//signed token and then encrypt the singed token use symmetric key between groupServer and user
							byte[] signedTokenHash= signature(hashObject);

							enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
							SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
					        enc.init(Cipher.ENCRYPT_MODE, secretKeySpec);
					        byte[] IV= enc.getIV();
					        //we need to share a same IV with client, so we first send IV
                                                dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                                dec.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));

                                                ByteToken IVToken= new ByteToken(IV);
					        output.writeObject(IVToken);

					        byte[] encryptedHash= enc.doFinal(signedTokenHash);
					        //create a ByteToken object which contain the encrypted and singed token
					        ByteToken bytetoken= new ByteToken(encryptedHash);
					        response.addObject(bytetoken);
							output.writeObject(response);
							//we send a encrypted token, it is not signed
							byte[] encryptedToken = enc.doFinal(serializedObject);
							ByteToken enve= new ByteToken(encryptedToken);
							output.writeObject(enve);

							KeyGenerator keyGen = KeyGenerator.getInstance("AES");
							keyGen.init(128);
							SecretKey aesKey = keyGen.generateKey();
							Cipher tokenCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
							tokenCipher.init(Cipher.ENCRYPT_MODE,aesKey);
							byte[] signedKey = signature(aesKey.getEncoded());
							byte[] eToken = tokenCipher.doFinal(serializedObject);
							Envelope content = new Envelope("content");
							content.addObject(signedKey);
							content.addObject(aesKey);
							content.addObject(tokenCipher.getIV());
							content.addObject(eToken);
							response = new Envelope("OK");
							response.addObject(encrypt(content));
							output.writeObject(response);

						} catch (Exception e) {
							System.out.println(e+" group server send token");
							e.printStackTrace();
						}

					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							SealedObject obj= (SealedObject)(message.getObjContents().get(0));
							byte[] hmac = (byte[]) message.getObjContents().get(1);
							if(!Arrays.equals(hmac(obj),hmac))	socket.close();
							Envelope content= decrypt(obj);
							if(content.getObjContents().get(0) != null)
							{
								String username = (String)content.getObjContents().get(0); //Extract the username
								String password = (String) content.getObjContents().get(1);
								UserToken yourToken = (UserToken)content.getObjContents().get(2); //Extract the token
								Integer received_sequnce = (Integer)content.getObjContents().get(3);
								if(!received_sequnce.equals(sequence))	{
									response = new Envelope("REORDER");  //reorder happens
								}else if(createUser(username, password,yourToken)) {
									response = new Envelope("OK"); //Success
									Envelope e = new Envelope("OK");
									e.addObject(sequence);
									response.addObject(encrypt(e));
									response.addObject(hmac(encrypt(e)));
								}
							}
						}
					}
					output.writeObject(response);
					sequence ++;
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{

					if(message.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							SealedObject obj= (SealedObject)(message.getObjContents().get(0));
							byte[] hmac = (byte[]) message.getObjContents().get(1);
							if(!Arrays.equals(hmac,hmac(obj)))	socket.close();
							Envelope content= decrypt(obj);
							if(content.getObjContents().get(0) != null)
							{
								String username = (String)content.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)content.getObjContents().get(1); //Extract the token
								Integer received_sequence = (Integer)content.getObjContents().get(2);	//receive the sequence number
								if(!received_sequence.equals(sequence))	response = new Envelope("REORDER");
								else if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
									Envelope e = new Envelope("OK");
									e.addObject(sequence);
									response.addObject(encrypt(e));
									response.addObject(hmac(encrypt(e)));
								}
							}
						}
					}

					output.writeObject(response);
					sequence++;
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    /* TODO:  Write this handler */
				    if(message.getObjContents().size()<1){
				    	response = new Envelope("Fail");
					}else{
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							SealedObject obj= (SealedObject)(message.getObjContents().get(0));
							byte[] hmac = (byte[]) message.getObjContents().get(1);
							if(!Arrays.equals(hmac,hmac(obj))) socket.close();
							Envelope content= decrypt(obj);
							if(content.getObjContents().get(1) != null)
							{
								String groupname = (String)content.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)content.getObjContents().get(1); //Extract the token
								Integer received_sequence = (Integer)content.getObjContents().get(2);	//receive the sequence number
								if(!received_sequence.equals(sequence))	response = new Envelope("REORDER");
								else if(createGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
									Envelope e = new Envelope("OK");
									e.addObject(sequence);
									SealedObject encrypted = encrypt(e);
									response.addObject(encrypted);
									response.addObject(hmac(encrypted));
								}
							}
						}
					}
					output.writeObject(response);
				    sequence++;
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size()<1){
						response = new Envelope("Fail");
					}else{
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							SealedObject obj= (SealedObject)(message.getObjContents().get(0));
							byte[] hmac = (byte[]) message.getObjContents().get(1);
							if(!Arrays.equals(hmac,hmac(obj))) socket.close();
							Envelope content= decrypt(obj);
							if(content.getObjContents().get(1) != null)
							{
								String groupname = (String)content.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)content.getObjContents().get(1); //Extract the token
								Integer received_sequence = (Integer)content.getObjContents().get(2);	//receive the sequence number
								if(!received_sequence.equals(sequence))	response = new Envelope("REORDER");
								else if(deleteGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
									Envelope e = new Envelope("OK");
									e.addObject(sequence);
									SealedObject encrypted = encrypt(e);
									response.addObject(encrypted);
									response.addObject(hmac(encrypted));
								}
							}
						}
					}
					output.writeObject(response);
					sequence++;
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size()<1){
						response = new Envelope("Fail");
					}else{
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							SealedObject obj= (SealedObject)(message.getObjContents().get(0));
							byte[] hmac = (byte[]) message.getObjContents().get(1);
							if(!Arrays.equals(hmac,hmac(obj))) socket.close();
							Envelope content= decrypt(obj);
							if(content.getObjContents().get(1) != null)
							{
								String groupname = (String)content.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)content.getObjContents().get(1); //Extract the token
								Integer received_sequence = (Integer)content.getObjContents().get(2);	//receive the sequence number
								if(!received_sequence.equals(sequence)) response = new Envelope("REORDER");
								else{
									List<String> members = listMembers(groupname,yourToken);	//List all the members in the group
									if(members != null){
									response = new Envelope("OK"); //Success
									Envelope memberAll= new Envelope("content");
									memberAll.addObject(members);
									memberAll.addObject(sequence);
									SealedObject encrypted = encrypt(memberAll);
									response.addObject(encrypted);
									response.addObject(hmac(encrypted));
									}
								}
								}
							}
						}
					output.writeObject(response);
					sequence++;
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							SealedObject obj= (SealedObject)(message.getObjContents().get(0));
							byte[] hmac = (byte[]) message.getObjContents().get(1);
							if(!Arrays.equals(hmac,hmac(obj))) socket.close();
							Envelope content= decrypt(obj);
							if(content.getObjContents().get(1) != null)
							{
								String username = (String)content.getObjContents().get(0); //Extract the username
								String group= (String)content.getObjContents().get(1);
								UserToken yourToken = (UserToken)content.getObjContents().get(2); //Extract the token
								Integer received_sequence = (Integer)content.getObjContents().get(3);	//receive the sequence number
								if(!received_sequence.equals(sequence))	response = new Envelope("REORDER");
								else if(addToGroup(yourToken.getSubject(), username,group, yourToken))
								{
									response = new Envelope("OK"); //Success
									Envelope e = new Envelope("OK");
									e.addObject(sequence);
									SealedObject encrypted = encrypt(e);
									response.addObject(encrypted);
									response.addObject(hmac(encrypted));
								}
							}
						}
					}

					output.writeObject(response);
					sequence++;
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							SealedObject obj= (SealedObject)(message.getObjContents().get(0));
							byte[] hmac = (byte[]) message.getObjContents().get(1);
							if(!Arrays.equals(hmac,hmac(obj))) socket.close();
							Envelope content= decrypt(obj);
							if(content.getObjContents().get(1) != null)
							{
								String username = (String)content.getObjContents().get(0); //Extract the username
								String group= (String)content.getObjContents().get(1);
								UserToken yourToken = (UserToken)content.getObjContents().get(2); //Extract the token
								Integer received_sequence = (Integer)content.getObjContents().get(3);	//receive the sequence number
								if(!received_sequence.equals(sequence))	response = new Envelope("REORDER");
								else if(removeFromGroup(yourToken.getSubject(),username,group, yourToken))
								{
									response = new Envelope("OK"); //Success
									Envelope e = new Envelope("OK");
									e.addObject(sequence);
									SealedObject encrypted = encrypt(e);
									response.addObject(encrypted);
									response.addObject(hmac(encrypted));
								}
							}
						}
					}

					output.writeObject(response);
					sequence++;
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else if(message.getMessage().equals("EXKEY")){
					BigInteger clientKey = (BigInteger) message.getObjContents().get(0); //Get g^b mod p
					String username = (String)message.getObjContents().get(1);		//get usernmae
					if(clientKey == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else {
						//check if user exists
						try {
							if (my_gs.secrets.containsKey(username)) {
								BigInteger v = my_gs.secrets.get(username);
								SRP6Server server = new SRP6Server();
								server.init(p, g, v, new SHA256Digest(), new SecureRandom());
								BigInteger serverKey = server.generateServerCredentials();
								key = server.calculateSecret(clientKey).toByteArray();
								for (int i = 0; i < 16; i++) {
									symmetricKey[i] = key[i];
								}
								//System.out.println("\nThe DH key: ");
								response = new Envelope("OK");
								response.addObject(serverKey);
								output.writeObject(response);
							} else {
								response = new Envelope("FAIL"); //Server does not understand client request
								output.writeObject(response);
							}
						} catch (Exception e) {
							response = new Envelope("WRONG");
							output.writeObject(response);
						}
					}
				}else if(message.getMessage().equals("CHALLENGE")) {
					byte[] challenge = (byte[]) message.getObjContents().get(0); //Get the username


					byte[] iv = (byte[]) message.getObjContents().get(1);        //Get IV;
					if (challenge == null) {
                                            System.out.println("null challenge");
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}else{
						try{
							Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
							SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
							cipher.init(Cipher.DECRYPT_MODE,secretKeySpec,new IvParameterSpec(iv));
							byte[] decryptedChallenge = cipher.doFinal(challenge);
							byte[] number = (new Random().nextInt()+"").getBytes();
							secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
							cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
							cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
							byte[] encryptedChallenge = cipher.doFinal(number);
							response = new Envelope("OK");
							response.addObject(decryptedChallenge.clone());
							response.addObject(encryptedChallenge.clone());
							response.addObject(cipher.getIV());
							output.writeObject(response);
							response = (Envelope)input.readObject();
							if(response.getMessage().equals("OK"))
							{
								ArrayList<Object> temp = null;
								temp = response.getObjContents();
								challenge = (byte[])temp.get(0);
								String retrieved = new String(challenge);
								if(!retrieved.equals(new String(number))) System.out.println("Something is wrong");
							}
						}catch (BadPaddingException be){
							response = new Envelope("Wrong");
							output.writeObject(response);
						}
					}
				}	else if(message.getMessage().equals("HMACK")){
					SealedObject encrypted = (SealedObject)message.getObjContents().get(0);
					Envelope content = decrypt(encrypted);
					hmacKey = (byte[])content.getObjContents().get(0);
					String challenge = (String)content.getObjContents().get(1);
					message = new Envelope("OK");
					content = new Envelope("Challenge");
					content.addObject(hmac(challenge));
					message.addObject(encrypt(content));
					output.writeObject(message);
				}
                                else if(message.getMessage().equals("GETGROUPKEYS")){
                                       SealedObject encry= (SealedObject)message.getObjContents().get(0);
                                       Envelope content= decrypt(encry);
                                       String groupName= (String)content.getObjContents().get(0);
                                       Token token= (Token)content.getObjContents().get(1);

                                       List<String> groups= token.getGroups();
                                       boolean found= false;
                                       for(int i= 0; i< groups.size(); i++){
                                           if(groups.get(i).equals(groupName)){
                                               FileInputStream fis = new FileInputStream(groupName);
                                               ObjectInputStream in= new ObjectInputStream(fis);
                                               GroupN groupn= (GroupN)in.readObject();
                                               ArrayList<Entry> keys= groupn.getCipher();

                                               Envelope okResponse= new Envelope("OK");
                                               Envelope keysE= new Envelope("KEYS");
                                               keysE.addObject(keys);
                                               okResponse.addObject(encrypt(keysE));
                                               output.writeObject(okResponse);
                                               found= true;
                                               break;
                                           }
                                       }
                                       if(!found){
                                        Envelope okResponse= new Envelope("FAIL"); //Server does not understand client request
                                        output.writeObject(okResponse);
                                       }
                                }
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace();
		}
	}

	private boolean addToGroup(String adder, String username, String group, UserToken token)
	{
		if(my_gs.userList.checkUser(username)&&my_gs.userList.checkUser(adder))
		{
			//Get the user's groups
			ArrayList<String> groups = my_gs.userList.getUserGroups(adder);
			ArrayList<String> added_groups = my_gs.userList.getUserGroups(username);
			//requester needs to be an administrator
			if(groups.contains("ADMIN"))
			{
				//Does user already exist?
				if(added_groups.contains(group))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addGroup(username, group);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	private boolean removeFromGroup(String deleter, String username, String group, UserToken token) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		if(my_gs.userList.checkUser(username)&&my_gs.userList.checkUser(deleter))
		{
			//Get the user's groups
			ArrayList<String> groups = my_gs.userList.getUserGroups(deleter);
			ArrayList<String> delete_groups = my_gs.userList.getUserGroups(username);
			//requester needs to be an administrator
			if(groups.contains("ADMIN"))
			{
				//Does user already exist?
				if(delete_groups.contains(group))
				{
					my_gs.userList.removeGroup(username, group);

                                        FileInputStream fis = new FileInputStream(group);

                                        ObjectInputStream in= new ObjectInputStream(fis);
                                        GroupN groupn= (GroupN)in.readObject();
                                        groupn.addCipher();

                                        FileOutputStream fos = new FileOutputStream(group);

                                        ObjectOutputStream out= new ObjectOutputStream(fos);
                                        out.writeObject(groupn);

					return true;
				}
				else
				{
					return false;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}



	//Method to create tokens
	private UserToken createToken(String username,String serverID)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
				//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username),serverID);
			return yourToken;
		}
		else
		{
			return null;
		}
	}


	//Method to create a user
	private boolean createUser(String username, String password, UserToken yourToken) throws NoSuchAlgorithmException {
		String requester = yourToken.getSubject();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					byte[] salt = "salt".getBytes();
					SRP6VerifierGenerator gen = new SRP6VerifierGenerator();
					gen.init(p, g, new SHA256Digest());
					BigInteger v = gen.generateVerifier(salt,username.getBytes(),password.getBytes()); //generate g^w mod p
					my_gs.secrets.put(username,v);			//store in the group server
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		String serverID = yourToken.getServerID();
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup,serverID));
					}

					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					my_gs.secrets.remove(username);

					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to create a group
	private boolean createGroup(String groupname, UserToken token) throws FileNotFoundException, NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{
		String requester = token.getSubject();
		//check if the requester exists
		if(my_gs.userList.checkUser(requester)){
			ArrayList<String> groups = my_gs.userList.getUserGroups(requester);
			if(groups.contains(groupname))		return false;
			my_gs.userList.addOwnership(requester,groupname);
			my_gs.userList.addGroup(requester,groupname);

                        /*
                        create group symmetric key<groupname, key>, stored in file
                        */
			GroupN groupn= new GroupN();
                        groupn.addCipher();
                        ObjectOutputStream fileout= new ObjectOutputStream(new FileOutputStream(groupname));
                        fileout.writeObject(groupn);
                        fileout.close();


			System.out.println("Create Group: "+my_gs.userList.getUserGroups(requester));
			return true;
		}
		return false;
	}

	//Method to delete a group
	private boolean deleteGroup(String groupname, UserToken token){
		String requester = token.getSubject();
		//check if the requester exists
		if(my_gs.userList.checkUser(requester)){
			//requester needs to be the owner of the group
			ArrayList<String> ownership = my_gs.userList.getUserOwnership(requester);
			if (ownership.contains(groupname)){
				//all members shall remove the group
				Enumeration<String> usernames = my_gs.userList.getAllUsernames();
				while(usernames.hasMoreElements()) {
					String username = usernames.nextElement();
					ArrayList<String> groups = my_gs.userList.getUserGroups(username);
					if (groups.contains(groupname)) my_gs.userList.removeGroup(username, groupname);
				}
				my_gs.userList.removeGroup(requester,groupname);
				my_gs.userList.removeOwnership(requester,groupname);		//remove the group and ownership of the user

                                File file= new File(groupname);
                                file.delete();

				return true;
			}
		}
		return false;
	}

	//Method to list all members
	private List<String> listMembers(String group, UserToken token){
		ArrayList<String> members = new ArrayList<>();
		String requester = token.getSubject();
		//check if the requester exists
		if(my_gs.userList.checkUser(requester)){
			//check if the requester is the owner of group
			ArrayList<String> ownership = my_gs.userList.getUserOwnership(requester);
			if(ownership.contains(group)){
				Enumeration<String> usernames = my_gs.userList.getAllUsernames();
				while(usernames.hasMoreElements()) {
					String username = usernames.nextElement();
					ArrayList<String> groups = my_gs.userList.getUserGroups(username);
					if(groups.contains(group)) members.add(username);
				}
			}
		}
		return members;
	}
        public SealedObject encrypt(Envelope env)

	{
            SealedObject sealed= null;
            try{

		sealed = new SealedObject(env, enc);
            }
            catch(Exception e){
                  System.err.println("Encrypt Error");
            }
	    return sealed;

	}



	public Envelope decrypt(SealedObject sealed)

	{
            Envelope env= null;
            try{
		env = (Envelope)sealed.getObject(dec);
            }catch(Exception e){
                   System.err.println("Group server decrypt error");
            }
		return env;

	}

	public byte[] hmac(byte[] msgAry) {
		// get instance of the SHA Message Digest object.
		HMac hmac = new HMac(new SHA256Digest());
		byte[] result = new byte[hmac.getMacSize()];
		KeyParameter kp = new KeyParameter(hmacKey);
		hmac.init(kp);
		hmac.update(msgAry,0, msgAry.length);
		hmac.doFinal(result, 0);
		return result;
	}

	public byte[] hmac(Object object){
		return hmac(convertToBytes(object));
	}

	private byte[] convertToBytes(Object object){
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
			 ObjectOutput out = new ObjectOutputStream(bos)) {
			out.writeObject(object);
			return bos.toByteArray();
		}catch (Exception e){
			System.out.printf(e.getMessage());
		}
		return null;
	}

}
