import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public abstract class Server {
	
	protected int port;
	public String name;
	abstract void start() throws NoSuchProviderException, NoSuchAlgorithmException;
	
	public Server(int _SERVER_PORT, String _serverName) {
		port = _SERVER_PORT;
		name = _serverName; 
	}
	
		
	public int getPort() {
		return port;
	}
	
	public String getName() {
		return name;
	}

}
