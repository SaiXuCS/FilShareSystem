# Usage Instructions

## Running the Group Server

To start the Group Server:
 - Enter the directory containing `RunGroupServer.class`
 - Type `java RunGroupServer [port number]`

Note that the port number argument to `RunGroupServer` is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

## Running the File Server

To start the File Server:
 - Enter the directory containing `RunFileServer.class`
 - Type `java RunFileServer [port number]`

Note that the port number argument to `RunFileServer is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

## Resetting the Group or File Server

To reset the Group Server, delete the file `UserList.bin`

To reset the File Server, delete the `FileList.bin` file and the `shared_files/` directory.

## Running our client 
To start the Client:
 - Enter the directory containing 'ClientApp.class'
 - Type `java ClientApp [group server hostname] [file server hostname] [group port number] [file port number]`
 
 
Supported Methods:
Create user: create user by providing username you want to delete
Delete user: delete user by providing username you want to delete
Create group: provide group name you want to create
Delete group: provide group name you want to delete
Add user to group: first provide username and then provide groupname you want to add user to
Delete user from group: first provide username and then provide groupname you want to delete user from
List member of group: provide groupname, it will list all members of this group
Upload a file: provide the relative path of the file you want to upload, and then provide the Alias name you want the file to be called in fileserver, and then provide which group this file belogn to. 
Download file: provide the alias name of the file you want to download from fileserver, and then provide the relative path you want the file to be stored on your computer. 
Delete a file: provide alias file name stored in fileserver, it will delete file from filelist.bin
List files: it will list all files stored in filelist.bin
Disconnect: it will disconnect from file and group server




