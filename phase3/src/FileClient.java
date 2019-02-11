/* FileClient provides all the client functionality regarding the file server */

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileClient extends Client implements FileClientInterface {
	Key publicKey;
	byte[] symmetrickeyFileClient;
	byte[] hmacKey;
	byte[] IV;
	Cipher enc;
	int sequence = 0;
	public FileClient(){
		Security.addProvider(new BouncyCastleProvider());
		String RSAFile= "RSAKeys2.bin";
		
		ObjectInputStream rsaStream;
		RSAObject rsaObject;
		
		try
		{
			//System.out.println("Your Host addr: " + InetAddress.getLocalHost().getHostName()); 
			FileInputStream fis = new FileInputStream(RSAFile);
			
			rsaStream = new ObjectInputStream(fis);
			rsaObject = (RSAObject)rsaStream.readObject();
			publicKey= rsaObject.returnPublic();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("RSA2 file doesn't find");
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

	public boolean vierfyToken(byte[] signedToken, UserToken token,byte[] tokenEncrypted,SecretKey tokenKey, byte[] tokenKeySigned,byte[] tokenIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException{
		//we first generate symmetric key used between file client and file server
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        symmetrickeyFileClient= aesKey.getEncoded();
		enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
        enc.init(Cipher.ENCRYPT_MODE, aesKey);
        //generate IV we used in or AES
        IV= enc.getIV();
                
        Cipher cipher= Cipher.getInstance("RSA");
    	cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    	//use publicKey of file server to encrypt symmetric key 
        byte[] encryptedKey= cipher.doFinal(symmetrickeyFileClient);
        
        //serialize token object we get from group server
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
		ObjectOutputStream so = new ObjectOutputStream(bo);
		so.writeObject(token);
		so.flush();
		byte[] serializedToken = bo.toByteArray();
                
                
        //encrypt the token using symmetric key 
		byte[] encryptedToken= enc.doFinal(serializedToken);
		//create the object containing IV, symmetric, token
        FileToServer fileServerKey= new FileToServer(IV, encryptedKey, signedToken, encryptedToken,tokenEncrypted,tokenKey,tokenKeySigned,tokenIV);

		Envelope env = new Envelope("VERIFY"); 
	    env.addObject(fileServerKey);
		
	    //send encrypted key and iv and signed token
	    output.writeObject(env);
	    
	    Envelope resp= (Envelope)input.readObject();
	    if(resp.getMessage().equals("Ok")){
                Envelope testEnvelope= new Envelope("test");
                SealedObject test= encrypt(testEnvelope);
                output.writeObject(test);
                Envelope response= decrypt((SealedObject)input.readObject());
                if(response.getMessage().equals("safe"))
                    return true;
                else
                    return false;
	    }
	    else{
	    	return false;
	    }
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
		Envelope encryptedMessage = new Envelope("DELETEF");
		encryptedMessage.addObject(remotePath);
		encryptedMessage.addObject(token);
		encryptedMessage.addObject(sequence);
		SealedObject sealedMessage = encrypt(encryptedMessage);
		env.addObject(sealedMessage);
		env.addObject(hmac(sealedMessage));
	    try {
			output.writeObject(env);
			sequence++;
		    env = (Envelope)input.readObject();
		    
			if (env.getMessage().compareTo("OK")==0) {
				sealedMessage = (SealedObject)env.getObjContents().get(0);
				byte[] hmac = (byte[]) env.getObjContents().get(1);
				if(!Arrays.equals(hmac,hmac(sealedMessage)))	System.exit(1);
				Integer receivedSequence = (Integer)decrypt(sealedMessage).getObjContents().get(0);
				if(!receivedSequence.equals(sequence-1))	System.exit(1);
				System.out.printf("File %s deleted successfully\n", filename);				
			}else if(env.getMessage().equals("REORDER")) System.exit(1);
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
	    	
		return true;
	}
        public String getGroupName(String src, UserToken token) throws IOException, ClassNotFoundException{
            Envelope env= new Envelope("GETGROUPNAME");
            src= src.substring(1);
            env.addObject(src);
            env.addObject(token);
            output.writeObject(env);
            Envelope response= (Envelope)input.readObject();
            String groupName= (String)response.getObjContents().get(0);
            return groupName;
        }
	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
						Envelope encryptedMessage = new Envelope("DOWNLOADF");
						encryptedMessage.addObject(sourceFile);
						encryptedMessage.addObject(token);
						encryptedMessage.addObject(sequence);
						SealedObject sealedMessage = encrypt(encryptedMessage);
						env.addObject(sealedMessage);
						env.addObject(hmac(sealedMessage));
					    output.writeObject(env); 
						sequence++;
					    env = (Envelope)input.readObject();
					   
						while (env.getMessage().compareTo("CHUNK")==0) {
								sealedMessage = (SealedObject)env.getObjContents().get(0);
								byte[] hmac = (byte[]) env.getObjContents().get(1);
								if(!Arrays.equals(hmac,hmac(sealedMessage)))	System.exit(1);
								Envelope encrypted = decrypt(sealedMessage);
								Integer receivedSequence = (Integer)encrypted.getObjContents().get(2);
                                                                int encryptN= (Integer)encrypted.getObjContents().get(3);
								if(!receivedSequence.equals(sequence-1))	System.exit(1);
								else{
                                                                        Cipher decrypt;
                                                                        byte[] decry= (byte[])encrypted.getObjContents().get(0);
                                                                        for(int i= encryptN- 1; i>= 0; i--){
                                                                            SecretKey aes= ClientApp.entries.get(i).aesKey;
                                                                            byte[] iv= ClientApp.entries.get(i).iv;
                                                                            System.out.println("key in download is "+ aes);
                                                                            System.out.println("IV in upload is "+ new String(iv, StandardCharsets.UTF_8));
                                                                            decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                                                            decrypt.init(Cipher.DECRYPT_MODE, aes, new IvParameterSpec(iv));
                                                                            System.out.println("index is "+i);
                                                                            decry= decrypt.doFinal(decry);
                                                                        }
									fos.write(decry);
									System.out.printf(".");
									env = new Envelope("DOWNLOADF"); //Success
									Envelope e = new Envelope("DOWNLOADF");
									e.addObject(sequence);
									sealedMessage = encrypt(e);
									env.addObject(sealedMessage);
									env.addObject(hmac(sealedMessage));
									output.writeObject(env);
									sequence++;
									env = (Envelope)input.readObject();
								}
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
							sealedMessage = (SealedObject)env.getObjContents().get(0);
							byte[] hmac = (byte[]) env.getObjContents().get(1);
							if(!Arrays.equals(hmac,hmac(sealedMessage)))	System.exit(1);
							Envelope e = decrypt(sealedMessage);
							Integer receivedSequence = (Integer)e.getObjContents().get(0);
							if(!receivedSequence.equals(sequence-1))	System.exit(1);
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								e = new Envelope("OK");
								e.addObject(sequence);
								sealedMessage = encrypt(e);
								env.addObject(sealedMessage);
								env.addObject(hmac(sealedMessage));
								output.writeObject(env);
								sequence++;
						}else if(env.getMessage().equals("REORDER")){
							System.out.println("Reorder happens");
							System.exit(1);
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
				} catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				} catch (IllegalBlockSizeException ex) {
                Logger.getLogger(FileClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(FileClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(FileClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(FileClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(FileClient.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidAlgorithmParameterException ex) {
                Logger.getLogger(FileClient.class.getName()).log(Level.SEVERE, null, ex);
            }
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 Envelope encryptedMessage = new Envelope("LFILES");
			 encryptedMessage.addObject(token); //Add requester's token
			 encryptedMessage.addObject(sequence);
			 message = new Envelope("LFILES");
			 SealedObject sealedMessage = encrypt(encryptedMessage);
			 message.addObject(sealedMessage);
			 message.addObject(hmac(sealedMessage));
			 output.writeObject(message); 
			 sequence++;
			 e = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				 sealedMessage = (SealedObject)e.getObjContents().get(0);
				 byte[] hmac = (byte[]) e.getObjContents().get(1);
				 if(!Arrays.equals(hmac,hmac(sealedMessage)))	System.exit(1);
				 Integer receivedSequence = (Integer)decrypt(sealedMessage).getObjContents().get(1);
				 if(!receivedSequence.equals(sequence-1))	System.exit(1);
				return (List<String>)decrypt(sealedMessage).getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }else if(e.getMessage().equals("REORDER")) System.exit(1);
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 FileInputStream fis = new FileInputStream(sourceFile);
			 message = new Envelope("UPLOADF");
			 Envelope encryptedMessage = new Envelope("UPLOADF");
			 encryptedMessage.addObject(destFile);
			 encryptedMessage.addObject(group);
			 encryptedMessage.addObject(token); //Add requester's token
			 encryptedMessage.addObject(sequence);
			 SealedObject sealedMessage = encrypt(encryptedMessage);
			 message.addObject(sealedMessage);
			 message.addObject(hmac(sealedMessage));
			 output.writeObject(message);
			 sequence++;

			 
			 env = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
				 sealedMessage = (SealedObject)env.getObjContents().get(0);
				 byte[] hmac = (byte[]) env.getObjContents().get(1);
				 if(!Arrays.equals(hmac,hmac(sealedMessage)))	System.exit(1);
				 Envelope e = decrypt(sealedMessage);
				 Integer receivedSequence = (Integer)e.getObjContents().get(0);
				 if(!receivedSequence.equals(sequence-1))	System.exit(1);
				System.out.printf("Meta data upload successful\n");
				
			}else if(env.getMessage().equals("REORDER")) System.exit(1);
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
				 	encryptedMessage = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						break;
					}
                                 ArrayList<Entry> entries= ClientApp.entries;
                                 int encryptedNumber= entries.size();
                                 for(int i= 0; i< entries.size(); i++){
                                    
                                     Entry entry= entries.get(i);
                                     SecretKey aes= entry.aesKey;
                                     byte[] iv= entry.iv;
                                      System.out.println("key in upload is "+ aes.toString());
                                      System.out.println("IV in upload is "+ new String(iv, StandardCharsets.UTF_8));
                                    Cipher enc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                    enc.init(Cipher.ENCRYPT_MODE, aes, new IvParameterSpec(iv));
                                    byte[] encrypted = enc.doFinal(buf);
                                    buf= encrypted;
                                 }
				 encryptedMessage.addObject(buf);
				 encryptedMessage.addObject(n);
				 encryptedMessage.addObject(sequence);
                                 encryptedMessage.addObject(encryptedNumber);
                                 System.out.println("n: "+ encryptedNumber);
				 sealedMessage = encrypt(encryptedMessage);
				 message.addObject(sealedMessage);
				 message.addObject(hmac(sealedMessage));
				 output.writeObject(message);
				 sequence++;
					
					
					env = (Envelope)input.readObject();
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				Envelope content= new Envelope("content");
				content.addObject(sequence);
				sealedMessage = encrypt(content);
				 message.addObject(sealedMessage);
				 message.addObject(hmac(sealedMessage));
				output.writeObject(message);
				sequence++;
				env = (Envelope)input.readObject();
				if(env.getMessage().compareTo("OK")==0) {
					sealedMessage = (SealedObject)env.getObjContents().get(0);
					byte[] hmac = (byte[]) env.getObjContents().get(1);
					if(!Arrays.equals(hmac,hmac(sealedMessage)))	System.exit(1);
					Envelope e = decrypt(sealedMessage);
					Integer receivedSequence = (Integer)e.getObjContents().get(0);
					if(!receivedSequence.equals(sequence-1))	System.exit(1);
					System.out.printf("\nFile data upload successful\n");
				}else if(env.getMessage().equals("REORDER")) System.exit(1);
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch (FileNotFoundException e){
			System.out.println("Cannot Find the file specified");
			return false;
		}
		 catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

        public SealedObject encrypt(Envelope env)

	{

		//SecretKey key = new SecretKeySpec(symmetrickeyFileClient, "AES");

		

		//Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");

		//aes.init(Cipher.ENCRYPT_MODE, key);

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

		//Cipher aes = Cipher.getInstance("AES");

		//aes.init(Cipher.DECRYPT_MODE, key);

            Envelope env= null;
            try{
		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetrickeyFileClient, "AES");

		Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding");

	    dec.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));

		env = (Envelope)sealed.getObject(dec);
            }catch(Exception e){
				System.err.println("File client decrypt error "+e.getMessage());
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

	public boolean passChallenge() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, ClassNotFoundException, InvalidAlgorithmParameterException {
		Envelope message = null, response = null;
		String number = new Random().nextInt()+"";
		SecretKeySpec secretKeySpec = new SecretKeySpec(symmetrickeyFileClient, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		byte[] encryptedChallenge = cipher.doFinal(number.getBytes());
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
			//If there is a token in the Envelope, return it
			ArrayList<Object> temp = null;
			temp = response.getObjContents();
			//System.out.println(temp.size());
			if(temp.size() == 1)
			{
					/* dectypt using AES */
				byte[] challenge = (byte[])temp.get(0);
				String retrieved = new String(challenge);
				if(number.equals(retrieved))	return true;
				else	return false;
			}
		}
		return false;
	}
}

