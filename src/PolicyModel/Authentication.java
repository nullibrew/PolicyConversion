package PolicyModel;

public class Authentication {
	private String _authType;
	public Subject _authenticatedUsers;

	public String getauthType() {
		return this._authType;
	}

	public void setAuthType(String aAuthType) {
		this._authType = aAuthType;
	}
}