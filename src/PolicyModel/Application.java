package PolicyModel;

import java.util.Vector;
import PolicyModel.Policy;

public class Application {
	private String _name;
	private String _description;
	public Vector<Policy> _comprised = new Vector<Policy>();
	public Vector<String> _policyDescription = new Vector<String>();

	public String getName() {
		return this._name;
	}

	public void setName(String aName) {
		this._name = aName;
	}

	public String getDescription() {
		return this._description;
	}

	public void setDescription(String aDescription) {
		this._description = aDescription;
	}
}