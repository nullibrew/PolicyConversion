package PolicyModel;

import java.util.Date;

public class IdentityConstraint {
	private String _attributeName;
	private String _attributeType;
	public EnvironmentConstraints _constrainedBy;
	public String getattributeName() {
		return this._attributeName;
	}

	public void setattributeName(String aattributeName) {
		this._attributeName = aattributeName;
	}
	public String getattributeType() {
		return this._attributeType;
	}

	public void setattributeType(String aattributeType) {
		this._attributeType = aattributeType;
	}
}
