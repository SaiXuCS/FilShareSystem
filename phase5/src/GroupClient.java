/* Implements the GroupClient Interface */

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

public class GroupClient extends Client implements GroupClientInterface {
	byte[] symmetrickeyGroupClient;
	byte[] hmacKey;
	byte[] signedTokenKey;
	SecretKey tokenKey;
	byte[] tokenIV;
	byte[] tokenEncrypted;
	Key publicKey;
	byte[] signedToken;
        byte[] IV;
        Cipher dec;
        Cipher enc;
        int sequence;

	public GroupClient(){
		Security.addProvider(new BouncyCastleProvider());
		String RSAFile= "RSAKeys.bin";
		
		ObjectInputStream rsaStream;
		RSAObject rsaObject;
		
		try
		{
			//read group rsa key 
			FileInputStream fis = new FileInputStream(RSAFile);
			
			rsaStream = new ObjectInputStream(fis);
			rsaObject = (RSAObject)rsaStream.readObject();
			publicKey= rsaObject.returnPublic();
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
	}
	public void setClientGroupSymmetricKey(byte[] key){
		symmetrickeyGroupClient= key;
	}
	public boolean verifyGroupServer() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException{
		//create a random challenge and encrypt use private key of group server
		Envelope message= new Envelope("VerifyGroup");
		Random rand= new Random();
		String challenge= rand.nextInt(100000)+"";
		byte[] cc= challenge.getBytes();
                
                Cipher cipher= Cipher.getInstance("RSA");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                byte[] encrypted = cipher.doFinal(cc);
                message.addObject(encrypted);
                output.writeObject(message);
                //get response
                Envelope response= (Envelope)input.readObject();
                byte[] signed= (byte[])response.getObjContents().get(0);
                byte[] encryptediv= (byte[])response.getObjContents().get(1);

                cipher.init(Cipher.DECRYPT_MODE,publicKey);
                byte[] encryptedChallenge = cipher.doFinal(signed);
                
                Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetrickeyGroupClient, "AES");
		decipher.init(Cipher.DECRYPT_MODE,secretKeySpec,new IvParameterSpec(encryptediv));
		byte[] decryptedChallenge = decipher.doFinal(encryptedChallenge);
              
                for(int i= 0; i< decryptedChallenge.length; i++){
                    if(decryptedChallenge[i]!= cc[i]){
                        return false;
                    }
                }
                return true;

	}
	public BigInteger exchangeKey(BigInteger clientPublicKey, String username){
		try{
			/* encrypt public diffie hellman key using shared secret w */
			Envelope message = null, response = null;
			message = new Envelope("EXKEY");
			message.addObject(clientPublicKey);
			message.addObject(username);
			output.writeObject(message);

			//Get the response from the server
			response = (Envelope)input.readObject();
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it
				BigInteger temp = (BigInteger)response.getObjContents().get(0);
				//System.out.println(temp.size());
				if(temp != null)
				{
					/* dectypt using AES */

					BigInteger serverPublicKey = temp;
					return serverPublicKey;
				}
				}else if(response.getMessage().equals("WRONG")){
				System.out.println("Wrong Password.");
				System.exit(1);
			}
			return null;
		}catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	}
        public ArrayList<Entry> getGroupKeys(String groupName, UserToken token){
            try
			{
				Envelope message = null, content= null;
				//Tell the server to create a user
				message = new Envelope("GETGROUPKEYS");
                                content = new Envelope("content");
				content.addObject(groupName); //Add user name string
				content.addObject(token); //Add the requester's token
				SealedObject encrypted= encrypt(content);
                                message.addObject(encrypted);
				output.writeObject(message);
				
				Envelope okResponse = (Envelope)input.readObject();
                                if(okResponse.getMessage().equals("FAIL")){
                                       return null;
                                }
                                else if(okResponse.getMessage().equals("OK")){
                                    SealedObject aa= (SealedObject)okResponse.getObjContents().get(0);
                                    Envelope keysE= decrypt(aa);
                                    ArrayList<Entry> keys= (ArrayList<Entry>)keysE.getObjContents().get(0);
                                
                                    return keys;
                                }
                                else{
                                    return null;
                                }
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
        }  
	 public UserToken getToken(String username, String serverID)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(serverID);
			output.writeObject(message);
			//get IV used by group server to encrypt token
			ByteToken IVToken= (ByteToken)input.readObject();
			IV= IVToken.getToken();
			
			Envelope encryptedEnvelope= (Envelope)input.readObject();
			//we get encrypted signed Envelope, first step is to decrypt it
			if(encryptedEnvelope.getMessage().equals("OK")){
				ByteToken bytetoken= (ByteToken)encryptedEnvelope.getObjContents().get(0);
				byte[] encryptedToken= bytetoken.token; 
				//System.out.println("get encrypted signed token from server");
			SecretKeySpec secretKeySpec = new SecretKeySpec(symmetrickeyGroupClient, "AES");
		        dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
		        dec.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
		        //after decrpt, we get the signed token
		        signedToken= dec.doFinal(encryptedToken);
	
		        
		        //use group public key to decrypt signed envelope, the result is token hmac value
		        Cipher cipher= Cipher.getInstance("RSA");
				cipher.init(Cipher.DECRYPT_MODE,publicKey);
		        byte[] getHashValue = cipher.doFinal(signedToken);
		        
                 
		        
		        //we get encrypted envelop containing token, which is not signed
		        ByteToken encryptedEnvelopeToken= (ByteToken)input.readObject();
		        byte[] envelop= encryptedEnvelopeToken.getToken();
		        byte[] serializedEnvelop= dec.doFinal(envelop);

		        //deserialize token object
		        ByteArrayInputStream bis = new ByteArrayInputStream(serializedEnvelop);
		        ObjectInputStream in = new ObjectInputStream(bis);
		        Token originalToken= (Token)in.readObject();
		        
                        
                        
				Envelope tokenResponse = (Envelope) input.readObject();
				decrypt((SealedObject)tokenResponse.getObjContents().get(0));
				Envelope content  = decrypt((SealedObject)tokenResponse.getObjContents().get(0));
				byte[] signedKey = (byte[])content.getObjContents().get(0);
				SecretKey aesKey = (SecretKey)content.getObjContents().get(1);
				if(!verifySignature(signedKey,aesKey.getEncoded()))	{
					System.out.println("Signing Key is compromised");
					System.exit(1);
				}else{
					System.out.println("Key verify success. ");
				}
				byte[] iv = (byte[]) content.getObjContents().get(2);
				byte[] eToken = (byte[]) content.getObjContents().get(3);
				Cipher tokenCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				tokenCipher.init(Cipher.DECRYPT_MODE,aesKey,new IvParameterSpec(iv));
				bis = new ByteArrayInputStream(tokenCipher.doFinal(eToken));
				in = new ObjectInputStream(bis);
				Token receivedToken= (Token)in.readObject();
				tokenKey = aesKey;
				signedTokenKey = signedKey;
				tokenIV = iv;
				tokenEncrypted = eToken;
				return receivedToken;
				
			}
			else{
				return null;
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage()+"group client get token");
			// e.printStackTrace(System.err);
			return null;
		}
	 }
	 
	 public boolean createUser(String username, String password,UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
                                Envelope content= new Envelope("content");
                          
				content.addObject(username); //Add user name string
				content.addObject(password);	//Add user password
				content.addObject(token); //Add the requester's token
				content.addObject(sequence);
				SealedObject encrypted= encrypt(content);
				message.addObject(encrypted);
				message.addObject(hmac(encrypted));
				output.writeObject(message);
				sequence ++;
				response = (Envelope)input.readObject();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					encrypted = (SealedObject)response.getObjContents().get(0);
					Envelope e = decrypt(encrypted);
					byte[] hmac = (byte[])response.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(encrypted)))	System.exit(1);
					Integer receivedSequence = (Integer)e.getObjContents().get(0);
					if(!receivedSequence.equals(sequence-1))	System.exit(1);
					return true;
				}else if(response.getMessage().equals("REORDER")) System.exit(1);
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
                                Envelope content= new Envelope("content");
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				content.addObject(username); //Add user name
				content.addObject(token);  //Add requester's token
				content.addObject(sequence);		//get sequence number
				SealedObject encrypted= encrypt(content);
				message.addObject(encrypted);
				message.addObject(hmac(encrypted));
				output.writeObject(message);
				sequence++;
				response = (Envelope)input.readObject();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					encrypted = (SealedObject)response.getObjContents().get(0);
					Envelope e = decrypt(encrypted);
					byte[] hmac = (byte[])response.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(encrypted)))	System.exit(1);
					Integer receivedSequence = (Integer)e.getObjContents().get(0);
					if(!receivedSequence.equals(sequence-1))	System.exit(1);
					return true;
				}else if(response.getMessage().equals("REORDER")) System.exit(1);
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
                                Envelope content= new Envelope("content");
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				content.addObject(groupname); //Add the group name string
				content.addObject(token); //Add the requester's token
				content.addObject(sequence);
				SealedObject encrypted = encrypt(content);
				message.addObject(encrypted);
				message.addObject(hmac(encrypted));
				output.writeObject(message); 
				sequence++;
				response = (Envelope)input.readObject();
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					encrypted = (SealedObject)response.getObjContents().get(0);
					Envelope e = decrypt(encrypted);
					byte[] hmac = (byte[])response.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(encrypted)))	System.exit(1);
					Integer receivedSequence = (Integer)e.getObjContents().get(0);
					if(!receivedSequence.equals(sequence-1))	System.exit(1);
					return true;
				}else if(response.getMessage().equals("REORDER")) System.exit(1);
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				Envelope content= new Envelope("content");
				message = new Envelope("DGROUP");
				content.addObject(groupname); //Add group name string
				content.addObject(token); //Add requester's token
				content.addObject(sequence);
				SealedObject encrypted = encrypt(content);
				message.addObject(encrypted);
				message.addObject(hmac(encrypted));
				output.writeObject(message); 
				sequence++;
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					encrypted = (SealedObject)response.getObjContents().get(0);
					Envelope e = decrypt(encrypted);
					byte[] hmac = (byte[])response.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(encrypted)))	System.exit(1);
					Integer receivedSequence = (Integer)e.getObjContents().get(0);
					if(!receivedSequence.equals(sequence-1))	System.exit(1);
					return true;
				}else if(response.getMessage().equals("REORDER")) System.exit(1);
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 Envelope content= new Envelope("content");
                         
			 content.addObject(group); //Add group name string
			 content.addObject(token); //Add requester's token
			 content.addObject(sequence);
			 SealedObject encrypted = encrypt(content);
			 message.addObject(encrypted);
			 message.addObject(hmac(encrypted));
			 output.writeObject(message); 
			 sequence++;
			 response = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				 encrypted = (SealedObject)response.getObjContents().get(0);
				 Envelope e = decrypt(encrypted);
				 byte[] hmac = (byte[])response.getObjContents().get(1);
				 if(!Arrays.equals(hmac,hmac(encrypted)))	System.exit(1);;
				 Integer receivedSequence = (Integer)e.getObjContents().get(1);
				 if(!receivedSequence.equals(sequence-1))	System.exit(1);
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }else if(response.getMessage().equals("REORDER")) System.exit(1);
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				Envelope content= new Envelope("content");
				content.addObject(username); //Add user name string
				content.addObject(groupname); //Add group name string
				content.addObject(token); //Add requester's token
				content.addObject(sequence);
				SealedObject encrypted = encrypt(content);
				message.addObject(encrypted);
				message.addObject(hmac(encrypted));
				output.writeObject(message); 
				sequence++;
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					encrypted = (SealedObject)response.getObjContents().get(0);
					Envelope e = decrypt(encrypted);
					byte[] hmac = (byte[])response.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(encrypted)))	System.exit(1);;
					Integer receivedSequence = (Integer)e.getObjContents().get(0);
					if(!receivedSequence.equals(sequence-1))	System.exit(1);
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
                                
				Envelope content= new Envelope("content");
				content.addObject(username); //Add user name string
				content.addObject(groupname); //Add group name string
				content.addObject(token); //Add requester's token
                content.addObject(sequence);
                SealedObject encrypted = encrypt(content);
				message.addObject(encrypted);
				message.addObject(hmac(encrypted));
				output.writeObject(message);
				sequence++;
				response = (Envelope)input.readObject();
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					encrypted = (SealedObject)response.getObjContents().get(0);
					Envelope e = decrypt(encrypted);
					byte[] hmac = (byte[])response.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(encrypted)))	System.exit(1);;
					Integer receivedSequence = (Integer)e.getObjContents().get(0);
					if(!receivedSequence.equals(sequence-1))	System.exit(1);
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
         public SealedObject encrypt(Envelope env)

	{

		//SecretKey key = new SecretKeySpec(symmetrickeyFileClient, "AES");

		

		//Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");

		//aes.init(Cipher.ENCRYPT_MODE, key);
            
            
            SealedObject sealed= null;
            try{
                enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(symmetrickeyGroupClient, "AES");
		        enc.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
		sealed = new SealedObject(env, enc);
            }
            catch(Exception e){
				System.out.println("Error:"+e.getMessage());
				System.err.println("Encrypt Error");
            }

		return sealed;

	}

	

	public Envelope decrypt(SealedObject sealed)

	{

		//Cipher aes = Cipher.getInstance("AES");

		//aes.init(Cipher.DECRYPT_MODE, key);

            Envelope env= null;
            try{
                   dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
                   SecretKeySpec secretKeySpec = new SecretKeySpec(symmetrickeyGroupClient, "AES");
		        dec.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
		env = (Envelope)sealed.getObject(dec);
            }catch(Exception e){
                   System.err.println("group client decrypt error "+e.getMessage());
            }
		return env;

	}
	public boolean passChallenge() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException, InvalidAlgorithmParameterException {
		Envelope message = null, response = null;
		String number = new Random().nextInt()+"";
		byte[] array= number.getBytes();
		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetrickeyGroupClient, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		byte[] encryptedChallenge = cipher.doFinal(array);
		byte[] iv = cipher.getIV();
		message = new Envelope("CHALLENGE");
		message.addObject(encryptedChallenge.clone());
		message.addObject(iv);
		output.writeObject(message);
		//Get the response from the server

		response = (Envelope)input.readObject();
		//Successful response
		if(response.getMessage().equals("OK"))
		{
			System.out.println("Challenge is ok");
			//If there is a token in the Envelope, return it
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			//System.out.println(temp.size());
			if(temp.size() == 3)
			{
					/* dectypt using AES */
				byte[] challenge = (byte[])temp.get(0);
				byte[] receivedChallenge = (byte[]) temp.get(1);
				byte[] receivedIV = (byte[])temp.get(2);
				cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				secretKeySpec = new SecretKeySpec(symmetrickeyGroupClient, "AES");
				cipher.init(Cipher.DECRYPT_MODE,secretKeySpec,new IvParameterSpec(receivedIV));
				byte[] decryptedChallenge = cipher.doFinal(receivedChallenge);
				response = new Envelope("OK");
				response.addObject(decryptedChallenge.clone());
				output.writeObject(response);
				String retrieved = new String(challenge);
				if(number.equals(retrieved))	return true;
				else	return false;
			}
		}
		return false;
	}

	public boolean shareHmacKey() throws NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey aesKey = keyGen.generateKey();
		hmacKey = aesKey.getEncoded();
		Envelope env = new Envelope("HMACK");
		Envelope content = new Envelope("content");
		String challenge = ThreadLocalRandom.current().nextInt()+"";
		content.addObject(hmacKey);
		content.addObject(challenge);
		env.addObject(encrypt(content));
		output.writeObject(env);

		Envelope resp= (Envelope)input.readObject();
		SealedObject sealedMessage = (SealedObject)resp.getObjContents().get(0);
		content = decrypt(sealedMessage);
		byte[] hmac = (byte[])content.getObjContents().get(0);
		if(!Arrays.equals(hmac,hmac(challenge)))	System.exit(1);
		return true;
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
        

	private boolean verifySignature(byte[] signedKey, byte[] key){
		try{
			String RSAFileGroup= "RSAKeys.bin";
			FileInputStream fis = new FileInputStream(RSAFileGroup);
			ObjectInputStream rsaStream = new ObjectInputStream(fis);
			RSAObject rsaObject = (RSAObject)rsaStream.readObject();
			Key groupPublicKey= rsaObject.returnPublic();
			Cipher signer= Cipher.getInstance("RSA");
			signer.init(Cipher.DECRYPT_MODE,groupPublicKey);
			byte[] signedValue = signer.doFinal(signedKey);
			for(int i= 0; i< signedValue.length; i++){
				if(key[i]!= signedValue[i]){
					return false;
				}
			}
		}catch (Exception e){
			System.out.println("Verify Signature error "+e.getMessage());
		}
		return true;
	}

	private boolean compareToken(Token t1,Token t2){
		if(!t1.getSubject().equals(t2.getSubject()))	return false;
		if(!t1.getIssuer().equals(t2.getIssuer()))	return false;
		for(String g:t1.getGroups()) System.out.println(g);
		for(String g:t2.getGroups()) System.out.println(g);
		return true;
	}
}
