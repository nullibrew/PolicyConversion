package PolicyModel;

import java.util.Vector;

public class Subject {
	private String _name;
	public Vector<Authentication> _authenticatedUsers = new Vector<Authentication>();
	public Vector<Authorization> _authorizedUsers = new Vector<Authorization>();
	public Policy _applies;

	public String getname() {
		return this._name;
	}

	public void setName(String aName) {
		this._name = aName;
	}
}