package PolicyModel;

import java.util.Vector;
import PolicyModel.Subject;
import PolicyModel.URL;
import PolicyModel.Action;
import PolicyModel.EnvironmentConstraints;

public class Policy {
	private String policyId;
	private String permitType;
	private String protectionType;
	public Vector<Subject> _applies = new Vector<Subject>();
	public Vector<URL> _protects = new Vector<URL>();
	public Vector<Action> _definedActions = new Vector<Action>();
	public Vector<EnvironmentConstraints> _enforces = new Vector<EnvironmentConstraints>();
	public Vector<ConstraintGroup> _enforcesConstraints = new Vector<ConstraintGroup>();
	public Application _comprised;
	public Vector<String> _targetDescription = new Vector<String>();
	public Vector<String> _ruleDescription = new Vector<String>();
	public String getpolicyId() {
		return policyId;
	}

	public void setPolicyId(String policyId) {
		this.policyId = policyId;
	}
	public String getpermitType() {
		return permitType;
	}

	public void setpermitType(String permitType) {
		this.permitType = permitType;
	}
	public String getprotectionType() {
		return protectionType;
	}

	public void setprotectionType(String aprotectionType) {
		this.protectionType = aprotectionType;
	}
}