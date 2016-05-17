package PolicyModel;

import java.util.Vector;

public class ConstraintGroup {
	private String _combiningOperator;
	private String _name;
	private String _permittype;
	//public TemporalConstraint _constrainedByTemp = new TemporalConstraint();
	//public IPConstraint _constrainedByIP = new IPConstraint();
	//public IdentityConstraint _constrainedByID = new IdentityConstraint();
	public Vector<EnvironmentConstraints> _enforces = new Vector<EnvironmentConstraints>();
	public String getcombiningOperator() {
		return this._combiningOperator;
	}

	public void setcombiningOperator(String aOperator) {
		this._combiningOperator = aOperator;
	}
	public String getpermittype() {
		return this._permittype;
	}

	public void setpermittype(String aPermit) {
		this._permittype = aPermit;
	}
	public String getname() {
		return this._name;
	}

	public void setname(String aName) {
		this._name = aName;
	}
}
