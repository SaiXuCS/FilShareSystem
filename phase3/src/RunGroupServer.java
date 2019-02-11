/* Driver program for FileSharing Group Server */

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class RunGroupServer {
	
	public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (args.length> 0) {
			try {
				GroupServer server = new GroupServer(Integer.parseInt(args[0]));
				server.start();
			}
			catch (NumberFormatException e) {
				System.out.printf("Enter a valid port number or pass no arguments to use the default port (%d)\n", GroupServer.SERVER_PORT);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			}
		}
		else {
			GroupServer server = new GroupServer();
			server.start();
		}
	}
}
