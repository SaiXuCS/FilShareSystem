/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
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
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					String password = (String)message.getObjContents().get(1);
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username,password); //Create a token
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
<<<<<<< HEAD
						response.addObject(yourToken);
						output.writeObject(response);
=======
						//response.addObject(yourToken);
						
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
							//hashObject= Arrays.hashCode(serializedObject);
	
							
							//System.out.println("serialized array length: "+ serializedObject.length);
							//*******************
							//signed token and then encrypt the singed token use symmetric key between groupServer and user
							byte[] signedTokenHash= signature(hashObject);
	
							Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
							SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
					        enc.init(Cipher.ENCRYPT_MODE, secretKeySpec);
					        byte[] IV= enc.getIV();
					        //we need to share a same IV with client, so we first send IV
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
							
						} catch (Exception e) {
							System.out.println(e+" group server send token");
							e.printStackTrace();
						}
						
					}
					/*
					// serialize the envelop object which contain token to string
					byte[] serializedObject;
					int hashObject;
					try {
					    ByteArrayOutputStream bo = new ByteArrayOutputStream();
						ObjectOutputStream so = new ObjectOutputStream(bo);
						so.writeObject(yourToken);
						so.flush();
						serializedObject = bo.toByteArray();
						hashObject= Arrays.hashCode(serializedObject);
						byte[] hashArray= String.valueOf(hashObject).getBytes();
						/*
						System.out.println("Hash token:");
						for(byte b: hashArray){
							System.out.print(b);
						}
						
						//System.out.println("serialized array length: "+ serializedObject.length);
						//*******************
						//signed envelop containing token and then encrypt the singed envelop use symmetric key between groupServer and user
						byte[] signedTokenHash= signature(hashArray);
		
						Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
						SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricKey, "AES");
				        enc.init(Cipher.ENCRYPT_MODE, secretKeySpec);
				        byte[] IV= enc.getIV();
				        
				        ByteToken IVToken= new ByteToken(IV);
				        output.writeObject(IVToken);
				        
				        byte[] encryptedHash= enc.doFinal(signedTokenHash);
				        //create a ByteToken object which contain the encrypted and singed envelope, in envelop, we store the token for user
				        ByteToken bytetoken= new ByteToken(encryptedHash);
				        
						output.writeObject(bytetoken);
						
						byte[] encryptedEnvelop = enc.doFinal(serializedObject);
						ByteToken enve= new ByteToken(encryptedEnvelop);
						output.writeObject(enve);
						
					} catch (Exception e) {
						System.out.println(e+" group server send token");
						e.printStackTrace();
>>>>>>> origin/changeHash
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								String password = (String) message.getObjContents().get(1);
								UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
								
								if(createUser(username, password,yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    /* TODO:  Write this handler */
				    if(message.getObjContents().size()<2){
				    	response = new Envelope("Fail");
					}else{
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(createGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size()<2){
						response = new Envelope("Fail");
					}else{
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(deleteGroup(groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size()<2){
						response = new Envelope("Fail");
					}else{
						response = new Envelope("FAIL");
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the groupname
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								List<String> members = listMembers(groupname,yourToken);	//List all the members in the group
								if(members != null){
									response = new Envelope("OK"); //Success
									response.addObject(members);
								}
								}
							}
						}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								String group= (String)message.getObjContents().get(1);
								UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
								
								if(addToGroup(yourToken.getSubject(), username,group, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
					
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								String group= (String)message.getObjContents().get(1);
								UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
								
								if(removeFromGroup(yourToken.getSubject(),username,group, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
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
			e.printStackTrace(System.err);
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
	
	private boolean removeFromGroup(String deleter, String username, String group, UserToken token)
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
	private UserToken createToken(String username, String password)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			if(my_gs.secrets.get(username).equals(password)){			//check that the password matches
				//Issue a new token with server's name, user's name, and user's groups
				UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
				return yourToken;
			}else	return null;
		}
		else
		{
			return null;
		}
	}
	
	
	//Method to create a user
	private boolean createUser(String username, String password, UserToken yourToken)
	{
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
					my_gs.secrets.put(username,password);
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
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
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
	private boolean createGroup(String groupname, UserToken token){
		String requester = token.getSubject();
		//check if the requester exists
		if(my_gs.userList.checkUser(requester)){
			ArrayList<String> groups = my_gs.userList.getUserGroups(requester);
			if(groups.contains(groupname))		return false;
			my_gs.userList.addOwnership(requester,groupname);
			my_gs.userList.addGroup(requester,groupname);
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
}
