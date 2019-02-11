import java.util.*;



public class ClientApp

{
	
	public static void main(String [] args)

	{


		GroupClient gclient = new GroupClient();

		FileClient fclient = new FileClient();


		Scanner inScan = new Scanner(System.in);

		String hostname_group = args[0];

		String hostname_file= args[1];

		String username= "";
		String password="";
		int userflag = 0;

		
		if (args.length >= 4)	gclient.connect(hostname_group, Integer.parseInt(args[2]));
		else 	gclient.connect(hostname_group, GroupServer.SERVER_PORT);

		UserToken token = new Token(null, null, null);

		

		while (userflag == 0)

		{

			System.out.print("Please enter your username: ");
			username = inScan.nextLine();
			System.out.print("Please enter your password: ");
			password = inScan.nextLine();
			token = gclient.getToken(username,password);

			

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
			token = gclient.getToken(username,password);

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
				for (String member : members) System.out.println(member);

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
