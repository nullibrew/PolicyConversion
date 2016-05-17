package PolicyModel;

import java.util.Vector;
import PolicyModel.Policy;

public class PolicySet {
	private String _name;
	private String _description;
	private String _polCombiningAlg;
	public Vector<Policy> _consistsOf = new Vector<Policy>();

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

	public String getPolCombiningAlg() {
		return this._polCombiningAlg;
	}

	public void setPolCombiningAlg(String aPolCombiningAlg) {
		this._polCombiningAlg = aPolCombiningAlg;
	}
}