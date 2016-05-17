package PolicyModel;

import java.util.ArrayList;
import java.util.Vector;

public class Authorization {
	private String _elementType;
	private Vector<String> _ldapCondition;
	private String _elementName;
	public Subject _authorizedUsers;

	public String getelementType() {
		return this._elementType;
	}

	public void setElementType(String aElementType) {
		this._elementType = aElementType;
	}

	public String getelementName() {
		return this._elementName;
	}
	public void setElementName(String aElementName) {
		this._elementName = aElementName;
	}	
 
	public void setldapCondition(ArrayList aLDAPCond) {
		for(int i=0;i<aLDAPCond.size();i++) {
			_ldapCondition.add((String)aLDAPCond.get(i));
		}
	}
}