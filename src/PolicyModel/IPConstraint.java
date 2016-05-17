package PolicyModel;

public class IPConstraint {
	private String _startRange;
	private String _endRange;
	private String _permittype;
	//public EnvironmentConstraints _constrainedBy;

	public String getstartRange() {
		return this._startRange;
	}

	public void setstartRange(String astartRange) {
		this._startRange = astartRange;
	}
	public String getendRange() {
		return this._endRange;
	}

	public void setendRange(String aendRange) {
		this._endRange = aendRange;
	}
	public String getpermittype() {
		return this._permittype;
	}

	public void setpermittype(String apermittype) {
		this._permittype = apermittype;
	}
}
