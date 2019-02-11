/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.*;
import java.lang.Thread;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class FileThread extends Thread
{
	private final Socket socket;
	Key publicKey;
	Key privateKey;
	Key groupPublicKey;
	String RSAFile= "RSAKeys2.bin";
	String RSAFileGroup= "RSAKeys.bin";
	RSAObject rsaObject;
	ObjectInputStream rsaStream;
	
	byte[] symmetricClientFile;
	byte[] symmetricIV;
	byte[] hmacKey;
	Token tokenVerified;
	Cipher dec;
	int sequence = 0;
	public FileThread(Socket _socket)
	{
		socket = _socket;
		//Open RSA file to get public and private key
		try
		{
			//System.out.println("Your Host addr: " + InetAddress.getLocalHost().getHostName()); 
			FileInputStream fis = new FileInputStream(RSAFile);
			rsaStream = new ObjectInputStream(fis);
			rsaObject = (RSAObject)rsaStream.readObject();
			publicKey= rsaObject.returnPublic();
			privateKey= rsaObject.returnPrivate();
			
			fis = new FileInputStream(RSAFileGroup);
			rsaStream = new ObjectInputStream(fis);
			rsaObject = (RSAObject)rsaStream.readObject();
			groupPublicKey= rsaObject.returnPublic();
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
	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());
				
				
				
				if(e.getMessage().equals("VERIFY")){
					//get filetoserver object from client, which contain token, key, iv
					FileToServer gerKeyFromClient= (FileToServer)(e.getObjContents().get(0));
					byte[] signedToken= gerKeyFromClient.signToken;
					byte[] encryptedSymmetricKey= gerKeyFromClient.key;
					byte[] IV= gerKeyFromClient.iv;
					byte[] encryptedToken= gerKeyFromClient.encryptedToken;
					
					//use file server private key to decrypt to get symmetric key
					Cipher cipher= Cipher.getInstance("RSA");
			    	cipher.init(Cipher.DECRYPT_MODE,privateKey);
			    	symmetricClientFile = cipher.doFinal(encryptedSymmetricKey);
			    	symmetricIV= IV;
			    	
                              
                                
			    	//use symmetric key to decrypt encrypted token
				SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricClientFile, "AES");
			        dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
			        dec.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
			        byte[] token= dec.doFinal(encryptedToken);
			    	
                                
                              
                                
			    	//use group public key to decrypt signed token to check whether it is sent by group server
			        Cipher signer= Cipher.getInstance("RSA");
			    	signer.init(Cipher.DECRYPT_MODE,groupPublicKey);
			    	byte[] tokenHashValue = signer.doFinal(signedToken);

                    MessageDigest digest= MessageDigest.getInstance("SHA-256");
					byte[] hashTokenArray= digest.digest(token);

					for(int i= 0; i< tokenHashValue.length; i++){
						if(tokenHashValue[i]!= hashTokenArray[i]){
							response= new Envelope("Fail");
							output.writeObject(response);
							return;
						}
					}
					/* get token from key, and make sure key is from group server */
					byte[] tokenEncrypted = gerKeyFromClient.tokenEncrypted;
					SecretKey tokenKey = gerKeyFromClient.tokenKey;
					byte[] tokenKeySigned = gerKeyFromClient.tokenKeySigned;
					byte[] tokenIV = gerKeyFromClient.tokenIV;
					if(verifySignature(tokenKeySigned,tokenKey.getEncoded())) System.out.println("Token key is verifyed");
					else socket.close();
					Cipher tokenCipher =Cipher.getInstance("AES/CBC/PKCS5Padding");
					tokenCipher.init(Cipher.DECRYPT_MODE,tokenKey,new IvParameterSpec(tokenIV));
					ByteArrayInputStream bis = new ByteArrayInputStream(tokenCipher.doFinal(tokenEncrypted));
					ObjectInputStream in = new ObjectInputStream(bis);
					tokenVerified = (Token)in.readObject();
					response= new Envelope("Ok");
					output.writeObject(response);
                                        
                                        Envelope getEncrypt= decrypt((SealedObject)input.readObject());
                                        if(getEncrypt.getMessage().equals("test")){
                                            Envelope safe= new Envelope("safe");
                                            SealedObject resp= encrypt(safe);
                                            output.writeObject(resp);
                                            /*encrypt*/                                   
                                        }
					
				}
				
				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    /* TODO: Write this handler */
					List<ShareFile> allFiles= FileServer.fileList.getFiles();
					SealedObject sealedMessage = (SealedObject)e.getObjContents().get(0);
					byte[] hmac = (byte[]) e.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(sealedMessage)))	socket.close();
					Envelope encrypted = decrypt(sealedMessage);
					UserToken usertoken= (UserToken)encrypted.getObjContents().get(0);
					Integer receivedSequence = (Integer)encrypted.getObjContents().get(1);
					Envelope response_envelop;
					if(!receivedSequence.equals(sequence))	{
						response_envelop = new Envelope("REORDER");  //reorder happens
					}else{
						List<String> userGroups = usertoken.getGroups();
						List<String> all_lists= new ArrayList<>();
						for(int i= 0; i< allFiles.size(); i++){
							ShareFile file= allFiles.get(i);
							if(userGroups.contains(file.getGroup())){
								all_lists.add(file.getPath());
							}
						}
						response_envelop= new Envelope("OK");
						Envelope encrypted_response = new Envelope("OK");
						encrypted_response.addObject(all_lists);
						encrypted_response.addObject(sequence);
						sealedMessage = encrypt(encrypted_response);
						response_envelop.addObject(sealedMessage);
						response_envelop.addObject(hmac(sealedMessage));
					}
					output.writeObject(response_envelop);
					sequence++;
				}
				if(e.getMessage().equals("UPLOADF"))
				{
					SealedObject sealedMessage = (SealedObject)e.getObjContents().get(0);
					byte[] hmac = (byte[]) e.getObjContents().get(1);
                                        
					if(!Arrays.equals(hmac,hmac(sealedMessage)))	socket.close();
					Envelope encrypted = decrypt(sealedMessage);
					if(encrypted.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(encrypted.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(encrypted.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(encrypted.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)encrypted.getObjContents().get(0);
							String group = (String)encrypted.getObjContents().get(1);
							UserToken yourToken = (UserToken)encrypted.getObjContents().get(2); //Extract token
							System.out.println(compareToken(tokenVerified,(Token)yourToken));
							Integer receivedSequence = (Integer)encrypted.getObjContents().get(3);
							if(!receivedSequence.equals(sequence))	{
								response = new Envelope("REORDER");  //reorder happens
							}
							else if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								for (String tokenGroup: yourToken.getGroups()){
									System.out.println(tokenGroup);
								}
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								Envelope seq = new Envelope("OK");
								seq.addObject(sequence);
								sealedMessage = encrypt(seq);
								response.addObject(sealedMessage);
								response.addObject(hmac(sealedMessage));
								output.writeObject(response);
								sequence++;
								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									sealedMessage = (SealedObject)e.getObjContents().get(0);
									hmac = (byte[]) e.getObjContents().get(1);
									if(!Arrays.equals(hmac,hmac(sealedMessage)))	socket.close();
									encrypted = decrypt(sealedMessage);
									receivedSequence = (Integer)encrypted.getObjContents().get(2);
                                                                        int encryptedNumber= (int)encrypted.getObjContents().get(3);
                                                                        FileNumber fileNumber= new FileNumber(encryptedNumber, remotePath);
                                                                        ObjectOutputStream fileout= new ObjectOutputStream(new FileOutputStream(remotePath.substring(1)));
                                                                        fileout.writeObject(fileNumber);
                                                                        fileout.close();
                                                                        System.out.println("number file: "+remotePath.substring(1));
									if(!receivedSequence.equals(sequence))	{
										response = new Envelope("REORDER");  //reorder happens
									}else{
                                                                                System.out.println("n: "+ encryptedNumber);
                                                                                //System.out.println("Upload file: "+new String((byte[])encrypted.getObjContents().get(0), StandardCharsets.UTF_8));
										fos.write((byte[])encrypted.getObjContents().get(0));
                                                                                fos.flush();
										response = new Envelope("READY"); //Success
									}
									output.writeObject(response);
									sequence++;
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									sealedMessage = (SealedObject)e.getObjContents().get(0);
									hmac = (byte[]) e.getObjContents().get(1);
									if(!Arrays.equals(hmac,hmac(sealedMessage)))	socket.close();
									Envelope content = decrypt(sealedMessage);
									receivedSequence = (Integer)content.getObjContents().get(0);
									if(!receivedSequence.equals(sequence))	response = new Envelope("REORDER");
									else{
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
										response = new Envelope("OK"); //Success
										content = new Envelope("OK");
										content.addObject(sequence);
										sealedMessage = encrypt(content);
										response.addObject(sealedMessage);
										response.addObject(hmac(sealedMessage));
									}
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
					sequence++;
				}
                                else if(e.getMessage().compareTo("GETGROUPNAME")== 0){
                                        String src= (String)e.getObjContents().get(0);
                                        UserToken token= (UserToken)e.getObjContents().get(1);
                                        
                                        ShareFile sf = FileServer.fileList.getFile("/"+src);
                                        String groupName= sf.getGroup();
                                        
                                        
                                        Envelope group= new Envelope("groupname");
                                        group.addObject(groupName);
                                        output.writeObject(group);
                                }
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {
					SealedObject sealedMessage = (SealedObject)e.getObjContents().get(0);
					byte[] hmac = (byte[]) e.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(sealedMessage)))	socket.close();
					Envelope encrypted = decrypt(sealedMessage);
					String remotePath = (String)encrypted.getObjContents().get(0);
					Token t = (Token)encrypted.getObjContents().get(1);
					Integer receivedSequence = (Integer)encrypted.getObjContents().get(2);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);
						sequence++;
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
						sequence++;
					}
					else {
						try
						{
                                                     
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);
							sequence++;
						}
						else {
							FileInputStream fis = new FileInputStream(f);
                                                       
                                                        double byteNumber = f.length();
                                                        
                                                        FileNumber fileNumber;
                                                        
                                                        System.out.println("number file: "+remotePath);
                                                        ObjectInputStream fileIn= new ObjectInputStream(new FileInputStream(remotePath));
                                                        fileNumber= (FileNumber)fileIn.readObject();
                                                        fileIn.close();
                                                        int encryptedN= fileNumber.n;
                                                        
							do {
                                                              
								byte[] buf = new byte[(int)byteNumber];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								if(!receivedSequence.equals(sequence))	 e = new Envelope("REORDER");
								else{
									e = new Envelope("CHUNK");
									encrypted = new Envelope("CHUNK");
									int n = fis.read(buf); //can throw an IOException
									if (n > 0) {
										System.out.printf(".");
									} else if (n < 0) {
										System.out.println("Read error");
									}
                                                                       // System.out.println("Donwload file: "+new String(buf, StandardCharsets.UTF_8));
									encrypted.addObject(buf);
									encrypted.addObject(n);
									encrypted.addObject(sequence);
                                                                        encrypted.addObject(encryptedN);
									sealedMessage = encrypt(encrypted);
									e.addObject(sealedMessage);
									e.addObject(hmac(sealedMessage));
								}
								output.writeObject(e);
								sequence++;
								e = (Envelope)input.readObject();
							}
							while (fis.available()>0);
							//If server indicates success, return the member list
							fis.close();
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								Envelope content = new Envelope("EOF");
								content.addObject(sequence);
								sealedMessage = encrypt(content);
								e.addObject(sealedMessage);
								e.addObject(hmac(sealedMessage));
								output.writeObject(e);
								sequence++;
								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									sealedMessage = (SealedObject)e.getObjContents().get(0);
									hmac = (byte[]) e.getObjContents().get(1);
									if(!Arrays.equals(hmac,hmac(sealedMessage)))	socket.close();
									Envelope env = decrypt(sealedMessage);
									receivedSequence = (Integer)env.getObjContents().get(0);
									if(!receivedSequence.equals(sequence)) socket.close();
									System.out.printf("File data upload successful\n");
									sequence++;
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

							}
						}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {
					SealedObject sealedMessage = (SealedObject)e.getObjContents().get(0);
					byte[] hmac = (byte[]) e.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(sealedMessage)))	socket.close();
					Envelope encrypted = decrypt(sealedMessage);
					String remotePath = (String)encrypted.getObjContents().get(0);
					Token t = (Token)encrypted.getObjContents().get(1);
					Integer receivedSequence = (Integer) encrypted.getObjContents().get(2);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if(!receivedSequence.equals(sequence))	e = new Envelope("REORDER");
					else if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

						try
						{


							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								e = new Envelope("OK");
								Envelope seq = new Envelope("OK");
								seq.addObject(sequence);
								sealedMessage = encrypt(seq);
								e.addObject(sealedMessage);
								e.addObject(hmac(sealedMessage));
							}
							else {
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					output.writeObject(e);
					sequence++;
				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}else if(e.getMessage().equals("CHALLENGE")) {
					byte[] challenge = (byte[]) e.getObjContents().get(0); //Get the username
					byte[] iv = (byte[]) e.getObjContents().get(1);        //Get IV;
					if (challenge == null) {
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}else{
						Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
						SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricClientFile, "AES");
						cipher.init(Cipher.DECRYPT_MODE,secretKeySpec,new IvParameterSpec(iv));
						byte[] decryptedChallenge = cipher.doFinal(challenge);
						response = new Envelope("OK");
						response.addObject(decryptedChallenge.clone());
						output.writeObject(response);
					}
				}
				else if(e.getMessage().equals("HMACK")){
					SealedObject encrypted = (SealedObject)e.getObjContents().get(0);
					Envelope content = decrypt(encrypted);
					hmacKey = (byte[])content.getObjContents().get(0);
					String challenge = (String)content.getObjContents().get(1);
					e = new Envelope("OK");
					content = new Envelope("Challenge");
					content.addObject(hmac(challenge));
					e.addObject(encrypt(content));
					output.writeObject(e);
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
        public SealedObject encrypt(Envelope env)

	{

		//SecretKey key = new SecretKeySpec(symmetrickeyFileClient, "AES");

		

		//Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");

		//aes.init(Cipher.ENCRYPT_MODE, key);
            
            SealedObject sealed= null;
            try{
                Cipher enc= Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricClientFile, "AES");
                enc.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(symmetricIV));
		sealed = new SealedObject(env, enc);
            }
            catch(Exception e){
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
		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetricClientFile, "AES");

		Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding");

	    dec.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(symmetricIV));

		env = (Envelope)sealed.getObject(dec);
            }catch(Exception e){
                   System.err.println("file thread decrypt error");
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
			System.out.println(e.getMessage());
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
