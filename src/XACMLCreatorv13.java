import java.util.Vector;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import PolicyModel.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class XACMLCreatorv13{
	public String xmlFile="<?xml version="+"\""+"1.0"+"\""+" encoding="+"\""+"UTF-8"+"\""+" standalone="+"\""+"yes"+"\""+"?>\n"; 
	Mapping map;
	XACMLCreatorv13(ModelPopulatorOAM mp, String outputPolicyFile){
		String xacmlClass;
		String xacmlAttrList;
		String delims;
		String[] attrs;
		Vector<Application> apps = new Vector();
		Vector<Policy> pols = new Vector();
		Vector<Subject> subjs = new Vector();
		Vector<URL> urls = new Vector();
		Vector<Action> acs = new Vector();
		Vector<EnvironmentConstraints> ecs = new Vector();
		Vector<ConstraintGroup> constGroup = new Vector();
		Vector<Authentication> auths = new Vector();
		Vector<Authorization> authzs = new Vector();
		// Create the models instances
		PrintWriter writer = null;
		FileWriter fstream = null;
		try {
			fstream = new FileWriter(outputPolicyFile);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		BufferedWriter out = new BufferedWriter(fstream);
		map = new Mapping();
		// Get the objects from the model instances
		apps = mp.appVec;
		xmlFile=xmlFile+createXACMLClassPolicySet("PolicySet");
		for (int appCount=0;appCount<apps.size();appCount++) {
			Application app = apps.elementAt(appCount);
			pols = app._comprised;
			for (int polCount=0;polCount<pols.size();polCount++) {
				String classDesc;
				String appStr="";
				String metadataDesc;
				Policy pol = pols.elementAt(polCount);
				xmlFile=xmlFile+createXACMLClass(pol,"Policy");
				appStr=createApplicationClassTarget(app.getName());
				appStr="<ns2:AnyOf>\n"+appStr+"</ns2:AnyOf>\n";
				subjs = pol._applies;
				urls = pol._protects;
				acs = pol._definedActions;
				ecs = pol._enforces;
				constGroup = pol._enforcesConstraints;
				String targetStrSub="";
				String ruleStrSub="";
				String targetStrAct="";
				String ruleStrAct="";
				String classDescURL="";
				for (int subjCount=0;subjCount<subjs.size();subjCount++) {
					Subject sub = subjs.elementAt(subjCount);
					targetStrSub=createSubjectClassTarget(sub); // A subject can be converted to only one target class
					ruleStrSub=createSubjectClassRule(sub, constGroup); // 
				}
				// Do the packaging
				targetStrSub="<ns2:AnyOf>\n"+targetStrSub+"</ns2:AnyOf>\n";
				for (int urlCount=0;urlCount<urls.size();urlCount++) {
					URL url = urls.elementAt(urlCount);
					classDescURL=classDescURL+createURLClass(url, app.getName());
				}
				classDescURL="<ns2:AnyOf>\n"+classDescURL+"</ns2:AnyOf>\n";
				for (int acCount=0;acCount<acs.size();acCount++) {
					Action ac = acs.elementAt(acCount);
					targetStrAct=targetStrAct+createActionClassTarget(ac,app.getName());
					ruleStrAct=ruleStrAct+createActionClassRule(ac, app.getName());
				}
				targetStrAct="<ns2:AnyOf>\n"+targetStrAct+"</ns2:AnyOf>\n";
				ruleStrAct="<ns2:Target>\n<ns2:AnyOf>\n"+ruleStrAct+"</ns2:AnyOf>\n</ns2:Target>\n";
				metadataDesc = createMetaData(app.getName());
				// Now do the packaging for this policy
				String policyDesc="<ns2:Target>\n"+targetStrSub+classDescURL+targetStrAct+appStr+"</ns2:Target>\n"+metadataDesc+"<ns2:Rule Effect="+"\""+"Permit"+"\""+" RuleId="+"\""+"null:permit-rule"+"\""+">\n"+ruleStrAct+ruleStrSub+"</ns2:Rule>\n</ns2:Policy>\n";
				xmlFile=xmlFile+policyDesc;
			}
		}
		xmlFile=xmlFile+"</ns2:PolicySet>\n";
		try {
			out.write(xmlFile);
			out.flush();
			out.close();
			System.out.println("Policy Generated Successfully");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("Error Writing the Output File");
			e.printStackTrace();
		}
		//System.out.println(xmlFile);
	}
	public String createApplicationClassTarget(String appName){
		String classDesc="";
        String matchID="urn:sun:opensso:application-match";
        String datatype="http://www.w3.org/2001/XMLSchema#string";
        String attributeID="urn:sun:opensso:application-id";
        String category="urn:sun:opensso:application-category";
        classDesc=classDesc+"<ns2:AllOf>\n<ns2:Match MatchId="+"\""+matchID+"\""+">\n";
        classDesc=classDesc+"<ns2:AttributeValue DataType="+"\""+datatype+"\""+">"+appName+"</ns2:AttributeValue>\n";
        classDesc=classDesc+"<ns2:AttributeDesignator MustBePresent="+"\""+false+"\""+" DataType="+"\""+datatype+"\""+" AttributeId="+"\""+attributeID+"\""+" Category="+"\""+category+"\""+"/>\n";
        classDesc=classDesc+"</ns2:Match>\n</ns2:AllOf>\n";
		return classDesc;
	}
	public String createURLClass(URL url, String appName){	
		String classDesc="";
        String matchID="urn:sun:opensso:entitlement:resource-match:application:"+appName;
        String datatype="http://www.w3.org/2001/XMLSchema#string";
        String attributeID="urn:oasis:names:tc:xacml:1.0:resource:resource-id";
        String category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource";
        classDesc=classDesc+"<ns2:AllOf>\n<ns2:Match MatchId="+"\""+matchID+"\""+">\n";
        classDesc=classDesc+"<ns2:AttributeValue DataType="+"\""+datatype+"\""+">"+url.geturl()+"</ns2:AttributeValue>\n";
        classDesc=classDesc+"<ns2:AttributeDesignator MustBePresent="+"\""+true+"\""+" DataType="+"\""+datatype+"\""+" AttributeId="+"\""+attributeID+"\""+" Category="+"\""+category+"\""+"/>\n";
        classDesc=classDesc+"</ns2:Match>\n</ns2:AllOf>\n";
		return classDesc;
	}
	public String createActionClassTarget(Action ac, String appName){	
		String targetStr="";
        String matchID="urn:sun:opensso:entitlement:action-match:application:"+appName;
        String datatype="http://www.w3.org/2001/XMLSchema#string";
        String attributeID="urn:oasis:names:tc:xacml:1.0:action:action-id";
        String category="urn:oasis:names:tc:xacml:3.0:attribute-category:action";
		targetStr=targetStr+"<ns2:AllOf>\n<ns2:Match MatchId="+"\""+matchID+"\""+">\n";
		targetStr=targetStr+"<ns2:AttributeValue DataType="+"\""+datatype+"\""+">"+ac.getactionType()+"</ns2:AttributeValue>\n";
		targetStr=targetStr+"<ns2:AttributeDesignator MustBePresent="+"\""+"true"+"\""+" DataType="+"\""+datatype+"\""+" AttributeId="+"\""+attributeID+"\""+" Category="+"\""+category+"\""+"/>\n";
		targetStr=targetStr+"</ns2:Match>\n</ns2:AllOf>\n";
		return targetStr;
	}
	public String createActionClassRule(Action ac, String appName){
		String ruleStr="";
        String matchID="urn:sun:opensso:entitlement:action-match:application:"+appName;
        String datatype="http://www.w3.org/2001/XMLSchema#string";
        String attributeID="urn:oasis:names:tc:xacml:1.0:action:action-id";
        String category="urn:oasis:names:tc:xacml:3.0:attribute-category:action";
		ruleStr=ruleStr+"<ns2:AllOf>\n<ns2:Match MatchId="+"\""+matchID+"\""+">\n";
		ruleStr=ruleStr+"<ns2:AttributeValue DataType="+"\""+datatype+"\""+">"+ac.getactionType()+"</ns2:AttributeValue>\n";
		ruleStr=ruleStr+"<ns2:AttributeDesignator MustBePresent="+"\""+"true"+"\""+" DataType="+"\""+datatype+"\""+" AttributeId="+"\""+attributeID+"\""+" Category="+"\""+category+"\""+"/>\n";
		ruleStr=ruleStr+"</ns2:Match>\n</ns2:AllOf>\n";
		return ruleStr;
	}
	public String createSubjectClassTarget(Subject sub){
		Vector<Authentication> auths;
		Vector<Authorization> authzs;
		auths = sub._authenticatedUsers;
		authzs = sub._authorizedUsers;
		String targetStr="";
		for (int authCount=0;authCount<auths.size();authCount++) {	
			String matchID="urn:sun:opensso:entitlement:json-subject-match";
			String attributeID="urn:sun:opensso:entitlement:json-subject";
			String category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
			String functionID="urn:sun:opensso:entitlement:json-subject-and-condiiton-satisfied";
			String privComponent="entitlementSubject";
			Authentication auth=auths.elementAt(authCount);	
			if (auth.getauthType().equals("NoSubject")){ // The resource's protection level is 'EXCLUDED'
				String datatype="urn:sun:opensso:entitlement:json-subject-type:com.sun.identity.entitlement.NoSubject";
				targetStr=targetStr+"<ns2:AllOf>\n<ns2:Match MatchId="+"\""+matchID+"\""+">\n";
				targetStr=targetStr+"<ns2:AttributeValue DataType="+"\""+datatype+"\""+">nosubject</ns2:AttributeValue>\n";
				targetStr=targetStr+"<ns2:AttributeDesignator MustBePresent="+"\""+"true"+"\""+" DataType="+"\""+datatype+"\"";
				targetStr=targetStr+" AttributeId="+"\""+attributeID+"\"";
				targetStr=targetStr+" Category="+"\""+category+"\""+"/>";
				targetStr=targetStr+"</ns2:Match>\n</ns2:AllOf>\n";
			}
			else { 	
				String datatype="urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.AuthenticatedUsers";
				targetStr=targetStr+"<ns2:AllOf>\n<ns2:Match MatchId="+"\""+matchID+"\""+">\n";
				targetStr=targetStr+"<ns2:AttributeValue DataType="+"\""+datatype+"\""+">{}</ns2:AttributeValue>\n";
				targetStr=targetStr+"<ns2:AttributeDesignator MustBePresent="+"\""+"true"+"\""+" DataType="+"\""+datatype+"\"";
				targetStr=targetStr+" AttributeId="+"\""+attributeID+"\"";
				targetStr=targetStr+" Category="+"\""+category+"\""+"/>";
				targetStr=targetStr+"</ns2:Match>\n</ns2:AllOf>\n";
			}
		}
		for (int authzCount=0;authzCount<authzs.size();authzCount++) {
			if (authzs!=null) {
				Authorization authz=authzs.elementAt(authzCount);
				String datatype="urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.IdentitySubject";
				String matchID="urn:sun:opensso:entitlement:json-subject-match";
				String attributeID="urn:sun:opensso:entitlement:json-subject";
				String category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
				targetStr=targetStr+"<ns2:AllOf>\n<Match MatchId="+"\""+matchID+"\""+">\n";
				targetStr=targetStr+"<ns2:AttributeValue DataType="+"\""+datatype+"\""+">"+authz.getelementName()+"</ns2:AttributeValue>\n";
				targetStr=targetStr+"<ns2:AttributeDesignator MustBePresent="+"\""+"true"+"\"" + " DataType="+"\""+datatype+"\"";
				targetStr=targetStr+" AttributeId="+"\""+attributeID+"\"";
				targetStr=targetStr+" Category="+"\""+category+"\""+"/>";
				targetStr=targetStr+"</ns2:Match>\n</ns2:AllOf>\n";
			}
		}
		return targetStr;
	}
	public String createSubjectClassRule(Subject sub, Vector<ConstraintGroup> constGroup){		
		Vector<Authentication> auths;
		Vector<Authorization> authzs;
		Vector<String> groupConstString;
		auths = sub._authenticatedUsers;
		authzs = sub._authorizedUsers;
		
		String functionID="urn:sun:opensso:entitlement:json-subject-and-condiiton-satisfied";
		String ruleStr="";
		String attrValString="";
		String ecattrValString="";
		String datatype="";
		String privComponent="entitlementCondition";
		String combinedString="";
		for (int authCount=0;authCount<auths.size();authCount++) {	
			if (auths!=null) { // This check is redundant, but will keep it for now
				Authentication auth=auths.elementAt(authCount);
				privComponent="entitlementSubject";
				String value = "";
				if (auth.getauthType().equals("Authenticated")) {
					value="{}";
				}
				else {
					value="nosubject";
				}
				attrValString=attrValString+"<ns2:AttributeValue DataType="+"\""+map.datatypeSubject.get(auth.getauthType())+"\""+" privilegeComponent="+"\""+privComponent+"\""+">"+value+"</ns2:AttributeValue>\n";
			}
		}
		for (int authzCount=0;authzCount<authzs.size();authzCount++) {	
			if (authzs!=null) {
				Authorization authz=authzs.elementAt(authzCount);
				String attributeID="urn:sun:opensso:entitlement:json-subject";
				String category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject";
				if (authz.getelementType()=="IdentitySubject") {
					privComponent="entitlementSubject";
					attrValString=attrValString+"<ns2:AttributeValue DataType="+"\""+map.datatypeSubject.get(authz.getelementType())+"\""+" privilegeComponent="+"\""+privComponent+"\""+">"+authz.getelementName()+"</ns2:AttributeValue>\n";
				}
				else {
					privComponent="entitlementCondition";
					attrValString=attrValString+"<ns2:AttributeValue DataType="+"\""+map.individualdatatypeCondition.get(authz.getelementType())+"\""+" privilegeComponent="+"\""+privComponent+"\""+">"+authz.getelementName()+"</ns2:AttributeValue>\n";
				}		
			}
		}
		String combinedwithOperatorString="";
		Vector<String> groupStrings = new Vector();
		String ultimateDatatype=""; // This datatype will be needed if there is only one group
		List<Hashtable<String,String>> attributeValueList = new ArrayList<Hashtable<String,String>>();
		for (int groupCounter=0;groupCounter<constGroup.size();groupCounter++){ // Should be atmost two
			String localDatatype = null;
			ConstraintGroup group = constGroup.elementAt(groupCounter);
			Hashtable<String, String> genericCondition = new Hashtable<String, String>();
			Hashtable<String, String> IdCondition = new Hashtable<String, String>();
			Hashtable<String, String> IPCondition = new Hashtable<String, String>();
			Hashtable<String, String> TemporalCondiiton = new Hashtable<String, String>();
		    String combOp = group.getcombiningOperator(); 
		    Vector<EnvironmentConstraints> ecs = group._enforces;
		    Vector<EnvironmentConstraints> origecs = new Vector();
		    Vector<String> indivCondStrings = new Vector();
		    Vector<IdentityConstraint> ids = new Vector();
		    int denyHere=0;
		    for (int ecCount=0;ecCount<ecs.size();ecCount++) {
		    	origecs.addElement(ecs.get(ecCount));
		    }
		    for (int ecCount=0;ecCount<ecs.size();ecCount++) {
			// Find all the Identity EC conditions
		    	EnvironmentConstraints ec = ecs.elementAt(ecCount);
		    	String cType=ec.getconstraintType();
		    	
		    	if (cType.equals("Identity")){ // Time related
		    		IdentityConstraint idc = ec._constrainedByID;
		    		ids.addElement(idc);
		    		ecs.removeElementAt(ecCount);
		    	} 
		    }
		    // Deal with the Identity constraints first
		    String idvalueString="";
		    
		    for (int idCount=0;idCount<ids.size();idCount++) {
		    	String IdStr;
		    	IdentityConstraint idc = ids.elementAt(idCount);
		    	String attrWithoutQuote=chopLastChar(idc.getattributeName().replaceAll("\\s",""));
	    		attrWithoutQuote=chopFirstChar(attrWithoutQuote);   
	    		String ldapType = "LDAPFilterCondition";
	    		localDatatype = ldapType;
	    		IdStr = "\\\\\\"+"\""+ "ldapFilter"+"\\\\\\"+"\""+": "+"\\\\\\"+"\""+attrWithoutQuote+"\\\\\\"+"\"";
	    		String ldapString = "LDAPFilterCondition"+":"+"ldapFilter";
	    		genericCondition.put(ldapString, attrWithoutQuote);
	    	}
		    for (int ecCount=0;ecCount<ecs.size();ecCount++) {
		    	privComponent="entitlementCondition";
		    	EnvironmentConstraints ec = ecs.elementAt(ecCount);
		    	String cType=ec.getconstraintType();
		    	localDatatype = cType;
		    	if (cType.equals("TemporalCondition")){ // Time related
		    		TemporalConstraint tc=ec._constrainedByTemp;
		    		String endT = "TemporalCondition"+":"+"endTime";
		    		String endD = "TemporalCondition"+":"+"endDay";
		    		String startT = "TemporalCondition"+":"+"startTime";
		    		String startD = "TemporalCondition"+":"+"startDay";
		    		genericCondition.put(endD, tc.getendDay());
		    		genericCondition.put(endT, tc.getendTime());
		    		genericCondition.put(startD, tc.getstartDay());
		    		genericCondition.put(startT, tc.getstartTime());
		    	} //NotCOn   memberE   IPV4
		    	else if (cType=="IPv4Condition"){ // IP Range
		    		IPConstraint ipc = ec._constrainedByIP;
		    		String endIP = "IPv4Condition"+":"+"endIp";
		    		String startIP = "IPv4Condition"+":"+"startIp";
		    		genericCondition.put(endIP, ipc.getendRange());
		    		genericCondition.put(startIP, ipc.getstartRange());
		    	}
		    }
		    attributeValueList.add(genericCondition);
		}

		String body="";
		Vector<String>conditions = new Vector();
		for (int groupCount=0;groupCount<constGroup.size();groupCount++) {
			String combOp = constGroup.get(groupCount).getcombiningOperator();
			String permittype = constGroup.get(groupCount).getpermittype(); 
			String singleConditionBody="";
			String condOp = "";
			Hashtable<String, String> genericCondition = new Hashtable<String, String>();
			Hashtable<String, String> IdCondition = new Hashtable<String, String>();
			Hashtable<String, String> IPCondition = new Hashtable<String, String>();
			Hashtable<String, String> TemporalCondition = new Hashtable<String, String>();
			genericCondition =attributeValueList.get(groupCount);
			Set<String> keys =genericCondition.keySet();
			Iterator<String> iterator = keys.iterator();
			int totalConditions = 0;
			int LDAPExist=0;
			int IPExist=0;
			int TemporalExist=0;
			if (combOp.equals("ALL")) {
				condOp = "ANDCondition";
			}
			else if (combOp.equals("ANY")) {
				condOp = "ORCondition";
			}
		    while(iterator.hasNext()) {
		        String key = iterator.next();
		        String value = genericCondition.get(key);
		        String delims = ":";
	    		String [] splitKey = key.split(delims);	
				if (splitKey[0].equals("LDAPFilterCondition")) {
					IdCondition.put(splitKey[1], value);
					if (LDAPExist==0) { // This is the first attribute of an LDAP condition
						totalConditions++;
					}
					LDAPExist=1;
				}
				else if (splitKey[0].equals("IPv4Condition")) {
					IPCondition.put(splitKey[1], value);
					if (IPExist==0) { // This is the first attribute of an IP condition
						totalConditions++;
					}
					IPExist=1;
				}
				else if (splitKey[0].equals("TemporalCondition")) {
					TemporalCondition.put(splitKey[1], value);
					if (TemporalExist==0) { // This is the first attribute of an Temporal condition
						totalConditions++;
					}
					TemporalExist=1;
				}
			}
		    int conditionLevel = 1;
		    if (permittype.equals("DENY")) {
	    		conditionLevel++;
	    	}
		    if (totalConditions>1){
		    	conditionLevel++;
		    }
		    if (constGroup.size()>1){
		    	conditionLevel++;
		    }
		    Vector<String>conds = new Vector();
		    Vector<String>classes = new Vector();
		    String conditionBody = buildConditionString(IdCondition, conditionLevel);
		    if (!(conditionBody.equals(""))) {
		    	conds.add(conditionBody); 
		    	classes.add(buildClassString("LDAPFilterCondition", conditionLevel-1));
		    }
		    conditionBody = buildConditionString(IPCondition, conditionLevel);
		    if (!(conditionBody.equals(""))) {
		    	conds.add(conditionBody); 
		    	classes.add(buildClassString("IPv4Condition", conditionLevel-1));
		    }
		    conditionBody = buildConditionString(TemporalCondition, conditionLevel);
		    if (!(conditionBody.equals(""))) {
		    	conds.add(conditionBody); 
		    	classes.add(buildClassString("TemporalCondition", conditionLevel-1));
		    }
		    if (constGroup.size()>1) {
		    	if (permittype.equals("DENY")) {
		    		String prefix1 =  buildPrefix(0); 
		    		String prefix2 =  buildPrefix(1);
		    		String prefix3 =  buildPrefix(2);
		    		String localConditionBody = "";
                    String denyInitial = prefix1 + "\""+"className"+prefix1+"\""+":"+ prefix1+ "\""+ map.compositedatatypeCondition.get("NOTCondition") + prefix1+"\""+", "+ prefix1 +"\""+ "state" +prefix1 +"\""+":"+prefix1 +"\""+"{"+ prefix2 +"\""+ "memberECondition"+ prefix2+"\""+":"+"{";
		    		if (totalConditions>1){
		    			String combInitial = denyInitial + prefix2 +"\""+ "className" +prefix2+"\""+":"+ prefix2+"\""+ map.compositedatatypeCondition.get(condOp)+prefix2+"\""+", "+ prefix2 +"\""+ "state" + prefix2+"\""+":"+prefix2+"\""+"{"+ prefix3+"\""+"memberECondition"+prefix3+"\""+":"+"[";
		    			for (int condCount=0;condCount<conds.size();condCount++) {
		    				if (localConditionBody.equals("")) {
		    					localConditionBody =  combInitial + "{"+ classes.get(condCount) + prefix3+"\""+"{"+ conds.get(condCount)+ "}"+ prefix3+"\""+"}";
		    				}
		    				else {
		    					localConditionBody =  localConditionBody + ", "+"{"+ classes.get(condCount) + prefix3+"\""+"{"+conds.get(condCount)+"}"+prefix3+"\""+"}";
		    				}
		    			}
		    			localConditionBody = localConditionBody + "]"+"}"+prefix2+"\""+"}"+"}"+prefix1+"\"";
		    		}
		    		else {
		    			localConditionBody =  denyInitial + classes.get(0) +prefix2+"\""+"{"+ conds.get(0)+"}"+prefix2+"\""+"}";
		    			localConditionBody = localConditionBody + "}"+prefix1+"\"";
		    		}
		    		singleConditionBody = singleConditionBody + localConditionBody;
		    	}
		    	else if (permittype.equals("ALLOW")){
		    		String localConditionBody = "";
		    		if (totalConditions>1) {
		    			String prefix1 =  buildPrefix(0); 
			    		String prefix2 =  buildPrefix(1);
			    		System.out.println("More than one");
                       	String allowInitial= prefix1 + "\""+"className" + prefix1+"\""+":"+ prefix1+"\""+ map.compositedatatypeCondition.get(condOp) + prefix1+"\""+", "+ prefix1 + "\""+ "state" +prefix1+"\""+":" + prefix1+"\""+"{"+prefix2+"\""+"memberECondition"+prefix2+"\""+":"+"[";
                       	for (int condCount=0;condCount<conds.size();condCount++) {
		    				if (localConditionBody.equals("")) {
		    					localConditionBody =  allowInitial + "{"+ classes.get(condCount) + prefix2+"\""+"{"+conds.get(condCount)+"}"+prefix2+"\""+"}";
		    				}
		    				else {
		    					localConditionBody =  localConditionBody + ", "+"{"+ classes.get(condCount) +prefix2+"\""+"{"+ conds.get(condCount)+"}"+prefix2+"\""+"}";
		    				}
		    			}
                       	localConditionBody = localConditionBody + "]"+"}"+prefix1+"\"";    			
		    		}
		    		else{
		    			String prefix1 =  buildPrefix(0);
		    			localConditionBody =  classes.get(0) + prefix1+"\""+"{"+ conds.get(0)+"}"+prefix1+"\"";
		    		}
		    		singleConditionBody = singleConditionBody + localConditionBody;
		    	}
		    }
		    else {
		    	if (permittype.equals("DENY")) {
		    		ultimateDatatype=map.individualdatatypeCondition.get("NOTCondition");
		    		String localConditionBody = "";
		    		if (totalConditions>1) {
		    			String prefix1 =  buildPrefix(0); 
			    		String prefix2 =  buildPrefix(1);
                       	String denyInitial ="{"+"\""+"memberECondition"+"\""+":"+"{"+ prefix1 +"\""+ "className" + prefix1+"\""+":"+prefix1+"\""+ map.compositedatatypeCondition.get(condOp) + prefix1+"\""+", "+ prefix1 +"\""+"state"+prefix1+"\""+":"+prefix1+"\""+"{"+prefix2 +"\""+"memberECondition"+prefix2+"\""+":"+"[";
                       	for (int condCount=0;condCount<conds.size();condCount++) {
		    				if (localConditionBody.equals("")) {
		    					localConditionBody =  denyInitial + "{"+ classes.get(condCount) + prefix2+"\""+"{"+conds.get(condCount)+"}"+prefix2+"\""+"}";
		    				}
		    				else {
		    					localConditionBody =  localConditionBody + ", "+"{"+ classes.get(condCount) + prefix2+"\""+"{"+conds.get(condCount)+"}"+prefix2+"\""+"}";
		    				}
		    			}
                       	localConditionBody = localConditionBody + "]"+"}"+prefix1+"\""+"}"+"}";  
		    		}
		    		else {
		    			String prefix1 =  buildPrefix(0); 
		    			String denyInitial ="{"+"\""+"memberECondition"+"\""+":"+"{";
		    			localConditionBody = denyInitial + classes.get(0) + prefix1+"\""+"{"+conds.get(0)+"}"+prefix1+"\"";
		    			localConditionBody = localConditionBody +"}"+"}";
		    		}
		    		singleConditionBody = singleConditionBody + localConditionBody;
		    	}
		    	else if (permittype.equals("ALLOW")) {	    		
		    		String localConditionBody = "";
		    		if (totalConditions>1) {
		    			String prefix1 =  buildPrefix(0);
		    			ultimateDatatype=map.individualdatatypeCondition.get(condOp);
                       	String allowInitial ="{"+"\""+"memberECondition"+"\""+":"+"[";
                       	for (int condCount=0;condCount<conds.size();condCount++) {
		    				if (localConditionBody.equals("")) {
		    					localConditionBody =  allowInitial + "{"+ classes.get(condCount) + prefix1+"\""+"{"+conds.get(condCount)+"}"+prefix1+"\""+"}";
		    				}
		    				else {
		    					localConditionBody =  localConditionBody + ", "+"{"+ classes.get(condCount) + prefix1+"\""+"{"+conds.get(condCount)+"}"+prefix1+"\""+"}";
		    				}
		    			}
                       	localConditionBody = localConditionBody + "]"+"}";   
		    		}
		    		else {
		    			ultimateDatatype=map.individualdatatypeCondition.get("LDAPFilterCondition");
		    			localConditionBody = "{"+ conds.get(0)+ "}";
		    		}
		    		singleConditionBody = singleConditionBody + localConditionBody;
		    	}
		    }
		    conditions.add(singleConditionBody);
		}
		/*
		 Case 1: One: Basically use the one from the earlier stage (during the individual 
               group stage). The datatype will be dependent on how many individual 
               constraints that group has and also the Deny/Allow and AND/OR:               
  		 Case 2: Two: Set the datatype as AND and combine them from the list (?)
          Body: memberECondition  
		 */
		if (constGroup.size()>1) {
			ultimateDatatype=map.individualdatatypeCondition.get("ANDCondition");
		}
		if (conditions.size()==1) {
			body = conditions.get(0);
			attrValString = "<ns2:AttributeValue DataType="+"\""+ultimateDatatype+"\""+ " privilegeComponent="+"\""+privComponent+"\""+">"+Util.encodeXmlAttribute(body)+"</ns2:AttributeValue>\n";
		}
		else {
			for (int groupCount=0;groupCount<conditions.size();groupCount++) {
				if (groupCount==0) {
					body = "{"+"\""+"memberECondition"+"\""+": [\n"+"{"+conditions.get(groupCount)+"}";
				}
				else {
					body=body+",{"+conditions.get(groupCount)+"}";
				}
			}
			body = body + "\n]}";
			attrValString = "<ns2:AttributeValue DataType="+"\""+ultimateDatatype+"\""+ " privilegeComponent="+"\""+privComponent+"\""+">"+Util.encodeXmlAttribute(body)+"</ns2:AttributeValue>\n";
		}
		// Now create the the full ruleStr
		ruleStr=ruleStr+"<ns2:Condition>\n<ns2:Apply FunctionId="+"\""+functionID+"\""+">\n";
		ruleStr=ruleStr+attrValString;
		ruleStr=ruleStr+"</ns2:Apply>\n</ns2:Condition>\n";
		return ruleStr;
	}
	public String buildPrefix(int conditionLevel) {
		if (conditionLevel == 2) {
			conditionLevel = 3;
		}
		else if (conditionLevel==3) {
			conditionLevel = 7;
		}
		String prefix = "";
		for (int levelCount=1;levelCount<=conditionLevel;levelCount++) {
        	prefix = prefix +"\\";
        }
		return prefix;
	}
	public String buildConditionString(Hashtable<String, String> genericCondition, int conditionLevel){
		// Get all the keys
		Set<String> keys = genericCondition.keySet();
		Iterator<String> iterator = keys.iterator();
		String pair = "";
		if (conditionLevel== 1) {
			conditionLevel = 0;
		}
		else if (conditionLevel==2) {
			conditionLevel = 1;
		}
		else if (conditionLevel== 3) {
			conditionLevel = 3;
		}
		else if (conditionLevel==4) {
			conditionLevel = 7;
		}
	    while(iterator.hasNext()) {
	        String key = iterator.next();
	        String value = genericCondition.get(key);
	        String prefix="";
	        for (int levelCount=1;levelCount<=conditionLevel;levelCount++) {
	        	prefix = prefix +"\\";
	        }
	        if (pair.equals("")) {
	        	pair = prefix + "\""+ key + prefix + "\""+":"+ prefix + "\""+ value + prefix + "\"" ;
	        }
	        else {
	        	pair = pair + ", "+ prefix + "\""+ key + prefix + "\""+":"+ prefix + "\""+ value + prefix + "\"";
	        }
	    }
		return pair;
	}
	public String buildClassString(String cond, int conditionLevel){
		String prefix="";
		String classString;
		if (conditionLevel== 1) {
			conditionLevel = 0;
		}
		else if (conditionLevel== 2) {
			conditionLevel = 1;
		}
		else if (conditionLevel==3) {
			conditionLevel = 3;
		}
		for (int levelCount=1;levelCount<=conditionLevel;levelCount++) {
			prefix = prefix +"\\";
	    }
		classString = prefix + "\""+ "className"+ prefix + "\""+":"+prefix + "\""+ map.compositedatatypeCondition.get(cond)+ prefix + "\""+", " + prefix + "\""+ "state"+ prefix + "\""+":";
		return classString;
	}
    public String createHardCodedAttributeList(String desc,String xacmlClass){
    	// This method will write the hard coded attributes for a XACML class 
    	// Input: The name of the XACML class
    	String attrVal="";
    	String xacmlAttrList;
    	String[] attrs;
    	xacmlAttrList = map.xacmlModelElement.get(xacmlClass);
		//Find the values for each of the attributes
    	if (xacmlAttrList!=null) {
    		String delims = ",";
    		attrs = xacmlAttrList.split(delims);
    		for (int i=0;i<attrs.length;i++) {
    			String finder = xacmlClass+":"+ attrs[i];
    			String hardCodedValue;
    			hardCodedValue = map.hardCodedAttributes.get(finder);
    			if (hardCodedValue!=null) {
    				xmlFile=xmlFile+attrs[i]+"="+"\""+hardCodedValue+"\""+" ";
    				desc=desc+attrs[i]+"="+"\""+hardCodedValue+"\""+" ";
    			}
    		}
    	}
    	return desc;
    }
    public String createContextAttribute(String desc, Object obj, String xacmlClass, String umlClass){
    	// This method will write the context specific attributes for a XACML class
    	// Input: i) The name of the UML class, ii) the context (App name, Policy, etc)
    	String attrVal="";
    	String xacmlAttrList;
    	String[] attrs;
    	xacmlAttrList = map.xacmlModelElement.get(xacmlClass);
		//Find the values for each of the attributes
    	if (xacmlAttrList!=null) {
    		String delims = ",";
    		attrs = xacmlAttrList.split(delims);	
    		for (int i=0;i<attrs.length;i++) {
    			String finder = xacmlClass+":"+ attrs[i];
    			String findString=finder+":"+umlClass; //findString=Match:matchID:Subject, AttributeValue:DataType:Subject
    			String contextValue;
    			contextValue = map.mapTable.get(findString);
    			// Deal with the string if the value is parameterized
    			if (contextValue!=null) { // Need to figure out this part, how to pass this value
    				if (contextValue.indexOf('$')>=0){
    		        // Find that parameter
    					String[] parts = contextValue.split("\\$");
    					String paramName = parts[1];
    			
    					String paramValue="";
    					// Find the appropriate value
    					if (paramName.equals("appName")) {
    						// Change the contextValue
    					}
    					else if (paramName.equals("polName")) {
    						// Change the contextValue
    					}
    					contextValue = parts[0]+paramValue;
    				} // end if
    				attrVal=contextValue;
    			}
    			if (attrVal!="") {
    				xmlFile=xmlFile+attrs[i]+"="+"\""+attrVal+"\""+" ";
    				desc=desc+attrs[i]+"="+"\""+attrVal+"\""+" ";
    			}
    		}
    	}
    	return desc;
    }
    public String createMappedAttribute(String desc, Object obj, String xacmlClass, String umlClass){
    	String[] xacmlPair;
    	String[] umlPair;
    	String[] mainPair;
    	String attrMapping;
    	for (String key : map.attributes.keySet()){ // For each of the key-attr pair of the hash
			String attrSeparator = ":";
			String contextSeparator = "\\+";
			String commaSeparator=",";
			mainPair = key.split(contextSeparator);
			attrMapping = map.attributes.get(key); // Action:actionType
			umlPair=attrMapping.split(attrSeparator);
			if (mainPair[1].equals(xacmlClass) && (mainPair[0].equals(umlClass))) { 
				// Now find the value
				String value="";
				String getterName="get"+umlPair[1];
				Method method = null;
				try {
					method = obj.getClass().getMethod(getterName, null);
				} catch (NoSuchMethodException | SecurityException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				try {
					value= (String) method.invoke(obj, null);
					
				} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				xmlFile=xmlFile+value+"\n";
				desc=desc+value+"\n";
			}	
		}  
    	return desc;
    }	
    public String createMappedElement(String desc, Object obj, String xacmlClass, String umlClass){
    	// This method will write the attributes for a XACML class that can be mapped to an UML attribute
    	// Input: i) The actual UML class object, ii) the name of the XACML class, iii) the name of the UML class
    	String[] xacmlPair;
    	String[] umlPair;
    	String[] mainPair;
    	String attrMapping;
    	for (String key : map.elements.keySet()){ // For each of the key-attr pair of the hash
			String attrSeparator = ":";
			String contextSeparator = "\\+";
			String commaSeparator=",";
			mainPair = key.split(contextSeparator);
			xacmlPair = mainPair[1].split(attrSeparator); // Policy:policyID
			attrMapping = map.elements.get(key); // Action:actionType
			umlPair=attrMapping.split(attrSeparator);
			if (xacmlPair[0].equals(xacmlClass) && (mainPair[0].equals(umlClass))) { 
				// Now find the value
				String value="";
				String getterName="get"+umlPair[1];
				Method method = null;
				try {
					method = obj.getClass().getMethod(getterName, null);
				} catch (NoSuchMethodException | SecurityException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				try {
					value= (String) method.invoke(obj, null);
					
				} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				String elementList = map.xacmlModelElement.get(xacmlPair[0]);
				String[] elements=elementList.split(commaSeparator);
				if ((Arrays.asList(elements).contains(xacmlPair[1]))) { //It's not an element, it's an attribute
					xmlFile=xmlFile+xacmlPair[1]+"="+"\""+value+"\""+" ";
					desc=desc+xacmlPair[1]+"="+"\""+value+"\""+" ";
				}
			}
			
		}
    	return desc;
    }
    
    public void createReferenceClass(Object obj, String classType){
    	// This method will create the elements classes which are part of the main class
    	// What about recursive structure
    	// This class may not be needed
    }
    public String createXACMLClassPolicySet(String indivClass){
    	String classDesc="";
    	String classType="PolicySet";
		classDesc=classDesc+"<"+"ns2:"+indivClass+" ";
		classDesc=createHardCodedAttributeList(classDesc,indivClass);
		classDesc=classDesc+">\n";
		return classDesc;
    }
	public String createXACMLClass(Object obj, String classType){
    	String xacmlClass;
		String xacmlAttrList;
		String delims;
		String[] attrs;
		String classDesc="";
		// Iterator objIt=obj.iterator();
		xacmlClass=map.classes.get(classType);
		delims = "\\+";
		String[] classNames = xacmlClass.split(delims);
		for (int i = 0; i < classNames.length; i++) {
			String classMapping=classNames[i];
			delims = ":";			
			String[] indivClasses = classMapping.split(delims);
			for (int j = indivClasses.length-1; j >= 0; j--) {
				xmlFile=xmlFile+"<"+"ns2:"+indivClasses[j]+" ";
				classDesc=classDesc+"<"+"ns2:"+indivClasses[j]+" ";
				classDesc=createHardCodedAttributeList(classDesc,indivClasses[j]);
				classDesc=createContextAttribute(classDesc,obj, indivClasses[j], classType);
				classDesc=createMappedElement(classDesc,obj, indivClasses[j], classType);
				xmlFile=xmlFile+">\n";
				classDesc=classDesc+">\n";
				classDesc=createMappedAttribute(classDesc,obj, indivClasses[j], classType);
				if (indivClasses[j].equals("Match")) { // Why this is a special case???
					// Find the attribute classes
					String attrClass;
					attrClass=map.xacmlModelClass.get(indivClasses[j]);
					String delim = ",";
					String[] indivAttrClasses = attrClass.split(delim);
					for (int count=0;count<=indivAttrClasses.length-1;count++) {
						xmlFile=xmlFile+"<"+indivAttrClasses[count]+" ";
						classDesc=classDesc+"<"+indivAttrClasses[count]+" ";
						classDesc=createHardCodedAttributeList(classDesc,indivAttrClasses[count]);
						classDesc=createContextAttribute(classDesc,obj, indivAttrClasses[count], classType);	
						classDesc=createMappedElement(classDesc,obj, indivAttrClasses[count], classType);
						xmlFile=xmlFile+">\n";
						classDesc=classDesc+">\n";
						classDesc=createMappedAttribute(classDesc,obj, indivAttrClasses[count], classType);
					}
				}
			}
		}
		return classDesc;
    }// end of createXACMLClass method
	public String chopLastChar(String phrase) {
		String rephrase = null;
	    if (phrase != null && phrase.length() > 1) {
	        rephrase = phrase.substring(0, phrase.length() - 1);
	    }
	    return rephrase;
	}
	public String chopFirstChar(String str) {
		return str.substring(1);
	}
	public String createMetaData(String appName){
		String policyMetadata="";
		String varDefStartTag="<ns2:VariableDefinition VariableId";
		String varDefEndTag="</ns2:VariableDefinition>";
		String attrDefStartTag="<ns2:AttributeValue DataType";
		String attrDefEndTag="</ns2:AttributeValue>";
		String adminUser="id=amadmin,ou=user,dc=openam,dc=forgerock,dc=org";
		String datatype = null;
		String value = null;
		Date currentTime=new Date();
		String[] attributeList={"applicationName","modifiedDate","modifiedBy","creationDate","createdBy"};
		for (int i=0;i<attributeList.length;i++) {
			String mappedValue = map.metadataAttributes.get(attributeList[i]);
			String valueType;
			if (attributeList[i].equals("applicationName")) {
				value = appName; 
				datatype="http://www.w3.org/2001/XMLSchema#string";
			}
			else if ((attributeList[i].equals("createdBy")||attributeList[i].equals("modifiedBy"))){
				value = adminUser;
				datatype = "http://www.w3.org/2001/XMLSchema#string";
			}
			else if ((attributeList[i].equals("creationTime")||attributeList[i].equals("modifiedTime"))){
				value = currentTime.toString();
				datatype= "http://www.w3.org/2001/XMLSchema#dataTime";
			}
			policyMetadata=policyMetadata+varDefStartTag+"="+"\""+mappedValue+"\">\n"+attrDefStartTag+"="+"\""+datatype+"\">"+value+attrDefEndTag+"\n"+varDefEndTag+"\n";
		}
		return policyMetadata;
	}
	
} //end Class XACMLCreatorv13
