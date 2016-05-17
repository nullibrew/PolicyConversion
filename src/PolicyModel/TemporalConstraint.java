package PolicyModel;

import java.util.Date;

public class TemporalConstraint {
	private String _startTime;
	private String _endTime;
	private String _startDay;
	private String _endDay;
	private String _permittype;
	public EnvironmentConstraints _constrainedBy;
	public String getstartTime() {
		return this._startTime;
	}

	public void setstartTime(String adate) {
		this._startTime = adate;
	}
	public String getendTime() {
		return this._endTime;
	}
	public void setendTime(String aendTime) {
		this._endTime = aendTime;
	}
	public String getstartDay() {
		return this._startDay;
	}

	public void setstartDay(String sday) {
		this._startDay = sday;
	}
	public String getendDay() {
		return this._endDay;
	}

	public void setendDay(String eday) {
		this._endDay = eday;
	}
	public String getpermittype() {
		return this._permittype;
	}

	public void setpermittype(String apermittype) {
		this._permittype = apermittype;
	}
}
