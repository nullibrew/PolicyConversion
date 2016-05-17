package PolicyModel;

import java.util.Vector;

public class EnvironmentConstraints {
	private String _constraintType;
	//private String _constraintName;
	//private String _constraintClass;
	public Policy _enforces;
	public TemporalConstraint _constrainedByTemp = new TemporalConstraint();
	public IPConstraint _constrainedByIP = new IPConstraint();
	public IdentityConstraint _constrainedByID = new IdentityConstraint();
	
	public String getconstraintType() {
		return this._constraintType;
	}

	public void setconstraintType(String aconstraintType) {
		this._constraintType = aconstraintType;
	}
	/*
	public String getconstraintName() {
		return this._constraintName;
	}

	public void setconstraintName(String aconstraintName) {
		this._constraintName = aconstraintName;
	}
	public String getconstraintClass() {
		return this._constraintClass;
	}

	public void setconstraintClass(String aconstraintClass) {
		this._constraintClass = aconstraintClass;
	}
	*/
}