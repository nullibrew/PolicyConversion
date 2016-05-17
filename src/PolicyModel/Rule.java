package PolicyModel;

import java.util.Vector;
import PolicyModel.IdentityCondition;
import PolicyModel.EnvironmentCondition;

public class Rule {
	private String _name;
	private String _effect;
	public Vector<IdentityCondition> _idSpecific = new Vector<IdentityCondition>();
	public Vector<EnvironmentCondition> _envSpecific = new Vector<EnvironmentCondition>();

	public String getName() {
		return this._name;
	}

	public void setName(String aName) {
		this._name = aName;
	}

	public String getEffect() {
		return this._effect;
	}

	public void setEffect(String aEffect) {
		this._effect = aEffect;
	}
}