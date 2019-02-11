import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Token implements UserToken, Serializable{
	
	private String issue;
	private String token_username;
	private List<String>token_usergroup;
	private String serverID;
	public Token(String issue_name, String username, ArrayList<String> userGroups, String serverID) {
		// TODO Auto-generated constructor stub
		this.issue= issue_name;
		this.token_username= username;
		this.token_usergroup = new ArrayList<>();
		if (userGroups != null){
			for (int i=0;i<userGroups.size();i++){
				token_usergroup.add(userGroups.get(i));
			}
		}
		this.serverID = serverID;
	}

//	public Token(String issue_name, String username, ArrayList<String> userGroups) {
//		// TODO Auto-generated constructor stub
//		this.issue= issue_name;
//		this.token_username= username;
//		this.token_usergroup = new ArrayList<>();
//		if (userGroups != null){
//			for (int i=0;i<userGroups.size();i++){
//				token_usergroup.add(userGroups.get(i));
//			}
//		}
//		serverID = "";
//	}

	@Override
	public String getIssuer() {
		// TODO Auto-generated method stub
		return issue;
	}

	@Override
	public String getSubject() {
		// TODO Auto-generated method stub
		return token_username;
	}

	@Override
	public List<String> getGroups() {
		// TODO Auto-generated method stub
		ArrayList<String> returnGroup = new ArrayList<>();
		if(token_usergroup != null){
			for(int i=0;i<token_usergroup.size();i++){
				returnGroup.add(token_usergroup.get(i));
			}
		}
		return returnGroup;
	}

	public String getServerID() {
		return serverID;
	}
}
