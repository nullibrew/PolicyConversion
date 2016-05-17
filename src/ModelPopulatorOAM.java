import java.util.*;
import java.io.*;
import org.yaml.snakeyaml.Yaml;
import PolicyModel.*;

public class ModelPopulatorOAM {
	Vector<Application> appVec = new Vector();
	ModelPopulatorOAM(String policyFileName){
		Yaml yaml = new Yaml();
		Vector<String>strVec = new Vector();
		try {
		     InputStream ios = new FileInputStream(new File(policyFileName));
		     // Parse the YAML file and return the output as a series of Maps and Lists
		     Map<String,ArrayList> result = (Map<String,ArrayList>)yaml.load(ios);
		     // Get the list of application domains
		     ArrayList domainList=result.get("Application Domains");
     		 // Get all the authorization policies
		 	 ArrayList authList=result.get("Authentication Policies");
		 	 ArrayList schemeList=result.get("Authentication Schemes");	
		 	 // Get all the authorization policies
		 	 ArrayList authzList=result.get("Authorization Policies");
		 	 ArrayList restypeList = result.get("Resource Types");
		     for (int domainCount=0;domainCount<domainList.size();domainCount++) {
		    	Vector<Policy>polVec = new Vector();
		    	LinkedHashMap dom = new LinkedHashMap();
		    	dom = (LinkedHashMap)domainList.get(domainCount);
		    	Application app = new Application();
     		 	app.setName((String)dom.get("domainname"));
		 		app.setDescription((String)dom.get("description"));
		 		 // Now get all the resources
		 		ArrayList resourceList=(ArrayList)dom.get("resource-list");
		 		// Get all the authentication policies
		 		for (int resourceCount=0;resourceCount<resourceList.size();resourceCount++) {
		 			Vector<URL>urlVec = new Vector();
			    	Vector<Subject> subVec = new Vector();
		 			LinkedHashMap res = (LinkedHashMap)resourceList.get(resourceCount);
		 			String restype;
		 			ArrayList resopList = null;
		 			Vector<Action>actVec = new Vector();
		 			Vector<Authorization> authzVec = new Vector();
		 			Vector<Authentication> authVec = new Vector();
		 			ArrayList opList=(ArrayList)((LinkedHashMap)resourceList.get(resourceCount)).get("operations");
					for (int opCount=0;opCount<opList.size();opCount++) {
						String op;
						op= ((LinkedHashMap)opList.get(opCount)).get("name").toString();
						Action act = new Action();
		 				act.setActionType(op);
		 				actVec.add(act);
					}
		 			Policy pol = new Policy();
		 			pol.setPolicyId((String)res.get("id"));
		 			Subject sub = new Subject();
		 			URL url1 = new URL();
		 			url1.setUrl((String)res.get("url"));
		 			urlVec.add(url1);
		 			pol._protects = urlVec;
		 			pol._definedActions=actVec;
		 			// If it is an unprotected page, then set the authentication condition as NoSubject, synonymous to anonymous auth
		 			if (((String)res.get("protectiontype")).equals("PROTECTED")||((String)res.get("protectiontype")).equals("UNPROTECTED")) {
		 				try {
		 					String authID=res.get("authentication").toString();
		 					Authentication auth = new Authentication();
		 					auth.setAuthType("Authenticated");
			 				authVec.add(auth);
		 				}catch (NullPointerException ne) {
		 				}
		 				String authzID="";
		 				try {
		 					authzID=res.get("authorization").toString();
		 					
		 				} catch (NullPointerException ne){
		 					
		 				}
		 				Authorization authz = new Authorization();
		 				// The resource is protected so find the authn and authz policies 
		 				// and attach to the policy
		 				int authzCondOnly=0;
		 				Vector<ConstraintGroup> cgGroup = new Vector<ConstraintGroup>();
		 				for (int authzCount=0;authzCount<authzList.size();authzCount++) {
		 					if (((LinkedHashMap)authzList.get(authzCount)).get("id").toString().equals(authzID)) {
		 						// Find all the constraints and fill up the following attributes
		 						ArrayList groupconstList=null;
		 						groupconstList=(ArrayList)((LinkedHashMap)authzList.get(authzCount)).get("constraints");
		 						int denyFound=0;
		 						try {
		 							for (int gconstCount=0;gconstCount<groupconstList.size();gconstCount++) {
		 								// Create authorization instance from each of the constraints
		 								// First decide whether it's a Env or Identity type constraint
		 								// String constClass= (String)((LinkedHashMap)groupconstList.get(gconstCount)).get("class");
		 								int numberofLDAPCond=0;
		 				 				
		 				 				int temporalCondExist=0;
		 				 				int ipCondExist=0;
		 				 				int LDAPFilterExist=0;
		 				 				int LDAPConditionExist=0;
		 				 				Vector<String>ldapConditionsDeny = new Vector();
		 				 				Vector<String>ldapConditionsAllow = new Vector(); 
		 								String LDAPString="";
		 								Vector<EnvironmentConstraints> ecVec = new Vector();
		 								String permittype= (String)((LinkedHashMap)groupconstList.get(gconstCount)).get("permittype");
		 								String condName= (String)((LinkedHashMap)groupconstList.get(gconstCount)).get("name");
		 								String combOp= (String)((LinkedHashMap)groupconstList.get(gconstCount)).get("combiningoperator");
		 								ArrayList condList=null;
		 								condList=(ArrayList)((LinkedHashMap)groupconstList.get(gconstCount)).get("conditions");
		 								for (int condCount=0;condCount<condList.size();condCount++) {
		 									String name = (String)((LinkedHashMap)condList.get(condCount)).get("name").toString();
		 									String condType = (String)((LinkedHashMap)condList.get(condCount)).get("conditiontype").toString();
		 									if (condType.equals("IDENTITY")){
		 										// Get the Identity type (User/group) and names
		 										ArrayList entityList=(ArrayList)((LinkedHashMap)condList.get(condCount)).get("Entities");
		 										for (int entityCount=0;entityCount<entityList.size();entityCount++) {
		 											String type;
		 											String ugname;
		 										
		 											LDAPConditionExist=1;
		 											type= ((LinkedHashMap)entityList.get(entityCount)).get("type").toString();
		 											ugname= ((LinkedHashMap)entityList.get(entityCount)).get("name").toString();
		 											if (type.equals("GROUP")) {
		 												String allowStr = "(memberOf="+ugname+")";
		 												ldapConditionsAllow.add(allowStr);
		 											}
		 											else if (type.equals("USER")){
		 												String allowStr = "(uid="+ugname+")";
		 												ldapConditionsAllow.add(allowStr);
		 											}
		 											else if (type.equals("ldapfilter")) {
		 												LDAPConditionExist=1;
		 												LDAPString=((LinkedHashMap)entityList.get(entityCount)).get("name").toString();
		 												LDAPFilterExist=1;
		 											}
		 										}
		 										if (LDAPConditionExist==1) { // Deal with the Identity authz different way as two or more constaints may be translated to a single authz instance
					 			 					if (LDAPFilterExist==0){
					 			 						String denyStr="";
					 			 						String allowStr="";
					 			 						int atleastOneDeny=0;
					 			 						int atleastOneAllow=0;
					 			 						for (int allowCount=0;allowCount<ldapConditionsAllow.size();allowCount++) {
					 			 							String str = ldapConditionsAllow.get(allowCount);
					 			 							allowStr = allowStr+str;
					 			 							atleastOneAllow=1;
					 			 						}
					 			 						if (ldapConditionsAllow.size()>0) {
					 			 							allowStr="(|"+allowStr+")";
					 			 						}
					 			 						if ((atleastOneDeny==1)&&(atleastOneAllow==1)) { // If both Allow and Deny conditions exist
					 			 							LDAPString="(&"+denyStr+allowStr+")";
					 			 						}
					 			 						else if (atleastOneAllow==1) {
					 			 							LDAPString = allowStr; 
					 			 						}
					 			 						else if (atleastOneDeny==1) 	{
					 			 							LDAPString = denyStr;
					 			 						}
					 			 						LDAPString="\""+LDAPString+"\"";
					 			 					}
					 			 					else {
					 			 						
					 			 						LDAPString="\""+LDAPString +"\"";
					 			 					}
					 	                            EnvironmentConstraints ec = new EnvironmentConstraints();
					 		 						ec.setconstraintType("Identity");
					 		 						ec._constrainedByID = new IdentityConstraint();
					 		 						ec._constrainedByID.setattributeType("LDAPFilterCondition");
					 		 						ec._constrainedByID.setattributeName(LDAPString);
					 								ecVec.add(ec);
					 							}
		 									}
		 									else if (condType.equals("TEMPORAL")){

		 										temporalCondExist=1;
		 										EnvironmentConstraints ec = new EnvironmentConstraints();
		 										ec.setconstraintType("TemporalCondition");
		 										String timeStart=((LinkedHashMap)condList.get(condCount)).get("Start Time").toString();
		 										String timeEnd=((LinkedHashMap)condList.get(condCount)).get("End Time").toString();
		 										String dayStart=((LinkedHashMap)condList.get(condCount)).get("Start Day").toString();
		 										String dayEnd=((LinkedHashMap)condList.get(condCount)).get("End Day").toString();
		 										TemporalConstraint tc = new TemporalConstraint();
		 										tc.setstartDay(dayStart);
		 										tc.setendDay(dayEnd);
		 										tc.setstartTime(timeStart);
		 										tc.setendTime(timeEnd);
		 										tc.setpermittype(condType);
		 										ec._constrainedByTemp = tc;
		 										ecVec.add(ec);
		 									}
		 									else if (condType.equals("IP4_RANGE")){
		 										ipCondExist=1;
		 										EnvironmentConstraints ec = new EnvironmentConstraints();
		 										ec.setconstraintType("IPv4Condition");
		 										String ipStart=((LinkedHashMap)condList.get(condCount)).get("IP Start").toString();
		 										String ipEnd=((LinkedHashMap)condList.get(condCount)).get("IP End").toString();
		 										IPConstraint ip = new IPConstraint();
		 										ip.setstartRange(ipStart);
		 										ip.setendRange(ipEnd);
		 										ip.setpermittype(condType);
		 										ec._constrainedByIP = ip;
		 										ecVec.add(ec);
		 									}
		 									// Attach the authz object to the policy
		 								}
			 							ConstraintGroup cg = new ConstraintGroup();
			 							cg.setcombiningOperator(combOp);
			 							cg.setpermittype(permittype);
			 							cg.setname(condName);
			 							cg._enforces = ecVec;
			 							cgGroup.add(cg);
		 							}
		 							
		 						} catch (NullPointerException ne) {
		 							// System.out.println("Null Pointer Exception for "+pol.getpolicyId());
		 							// ne.printStackTrace();
		 						}
		 					}
		 				}
		 				sub._authenticatedUsers = authVec;
		 				sub._authorizedUsers=authzVec;
		 				pol._enforcesConstraints = cgGroup;
		 				subVec.add(sub);		 			
		 				pol._applies = subVec;
		 			}
		 			else if (res.get("protectiontype").equals("EXCLUDED")){
		 				String authID=(String)res.get("authentication"); // It should be Null always
		 				Authentication auth = new Authentication();
		 				auth.setAuthType("NoSubject");
			 			authVec.add(auth);
			 			sub._authenticatedUsers = authVec;
			 			subVec.add(sub);
			 			pol._applies = subVec;
		 			}
		 		    polVec.add(pol);	
		 		}
				app._comprised = polVec;
		 		appVec.add(app); 
		     }
		   
		     
		    } catch (Exception e) {
		      e.printStackTrace();
		}
	}
}
