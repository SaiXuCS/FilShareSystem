/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class FileThread extends Thread
{
	private final Socket socket;

	public FileThread(Socket _socket)
	{
		socket = _socket;
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
<<<<<<< HEAD

=======
				
				
				
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
			        Cipher dec = Cipher.getInstance("AES/CBC/PKCS5Padding");
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
					
					response= new Envelope("Ok");
					output.writeObject(response);
					
				}
				
>>>>>>> origin/changeHash
				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    /* TODO: Write this handler */
					List<ShareFile> allFiles= FileServer.fileList.getFiles();
					UserToken usertoken= (UserToken)(e.getObjContents().get(0));
					List<String> userGroups = usertoken.getGroups();
					List<String> all_lists= new ArrayList<>();
					for(int i= 0; i< allFiles.size(); i++){
						ShareFile file= allFiles.get(i);
						if(userGroups.contains(file.getGroup())){
							all_lists.add(file.getPath());
						}
					}
					Envelope response_envelop= new Envelope("OK");
					response_envelop.addObject(all_lists);
					output.writeObject(response_envelop);
				}
				if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

							if (FileServer.fileList.checkFile(remotePath)) {
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
								output.writeObject(response);

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
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
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (e.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", e.getMessage());
									break;
								}
								e = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}


								e.addObject(buf);
								e.addObject(new Integer(n));

								output.writeObject(e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.writeObject(e);

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
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

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
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

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

}
