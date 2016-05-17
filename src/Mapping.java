
import java.util.Map;
import java.util.HashMap;
import java.util.Vector;
import java.util.Hashtable;
public class Mapping {
	public Hashtable<String, String> classes = new Hashtable<String, String>();
	public Hashtable<String, String> attributes = new Hashtable<String, String>();
	public Hashtable<String, String> hardCodedAttributes = new Hashtable<String, String>();
	public Hashtable<String, String> xacmlModelElement = new Hashtable<String, String>();
	public Hashtable<String, String> xacmlModelClass = new Hashtable<String, String>();
	public Hashtable<String, String> valueTable = new Hashtable<String, String>();
	public Hashtable<String, String> mapTable = new Hashtable<String, String>();
	public Hashtable<String, String> paramTable = new Hashtable<String, String>();
	public Hashtable<String, String> elements = new Hashtable<String, String>();
	public Hashtable<String, String> structure = new Hashtable<String, String>();
	public Hashtable<String, String> datatypeSubject = new Hashtable<String, String>();
	public Hashtable<String, String> individualdatatypeCondition = new Hashtable<String, String>();
	public Hashtable<String, String> compositedatatypeCondition = new Hashtable<String, String>();
	public Hashtable<String, String> metadataAttributes = new Hashtable<String, String>();
	Mapping(){
		classMapping();
		attributeMapping();
		hardcodedattributeMapping();
		xacmlElementSpecs();
		xacmlClassSpecs();
		valueMapping();
		contextValueMapping();	
		subjecttypeMapping();
		individualconditiontypeMapping();
		compositeconditiontypeMapping();
		elementMapping();
		metadataAttributesMapping();
	}
	public void classMapping(){
	    //classes.put("Application", "PolicySet");
	    classes.put("Policy", "Policy");
	    //classes.put("Subject", "Match:Allof:Anyof:Target+AttributeValue:Match:Allof:Anyof:Target:Rule");
	    classes.put("URL", "AttributeValue:Match:Allof");
	    //classes.put("Action", "AttributeValue:Match:Allof:Anyof:Target+AttributeValue:Match:Allof:Anyof:Target:Rule");
	    //classes.put("Authentication","AttributeValue:Apply:Condition:Rule");
	    //classes.put("Authorization","AttributeValue:Apply:Condition:Rule");
	    //classes.put("EnvironmentConstraints","AttributeValue:Apply:Condition:Rule");
	}
	public void xacmlStructure(){
		structure.put("PolicySet","Policy+");
		structure.put("Policy","Target,Rule");
	}
	public void attributeMapping(){
	    attributes.put("Action+AttributeValue", "Action:actionType");
	    attributes.put("URL+AttributeValue", "URL:url");
	    attributes.put("Subject+AttributeValue","Subject:name");   
	}
	public void elementMapping(){
		elements.put("Policy+Rule:Effect", "Policy:permitType");
	    elements.put("Policy+Policy:PolicyId", "Policy:policyId"); 
	}
	public void hardcodedattributeMapping(){
	    hardCodedAttributes.put("PolicySet:xmlns", "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17");
	    hardCodedAttributes.put("PolicySet:xmlns:ns2", "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17");
	    hardCodedAttributes.put("PolicySet:xmlns:xacml", "classpath:xsd/xacml-core-v3-schema-wd-17.xsd");
	    hardCodedAttributes.put("PolicySet:PolicyCombiningAlgId", "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides");
	    hardCodedAttributes.put("PolicySet:Version","2015.11.19.22.47.26.201");
	    hardCodedAttributes.put("Policy:RuleCombiningAlgId", "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides");
	    hardCodedAttributes.put("Policy:Version", "2015.11.19.22.46.58.332");     
	    hardCodedAttributes.put("ns2:PolicySet:xmlns", "urn:oasis:names:tc:xacml:3.0:core:schema:wd-17");
	    hardCodedAttributes.put("ns2:PolicySet:PolicyCombiningAlgId", "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides");
	    hardCodedAttributes.put("ns2:PolicySet:Version","2015.11.19.22.47.26.201");
	    hardCodedAttributes.put("ns2:Policy:RuleCombiningAlgId", "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides");
	    hardCodedAttributes.put("ns2:Policy:Version", "2015.11.19.22.46.58.332");     
	}
	public void xacmlElementSpecs(){
		//xacmlModelElement.put("PolicySet", "xmlns,PolicyCombiningAlgId,Version"); // OK
		//xacmlModelElement.put("Policy", "RuleCombiningAlgId,Version,PolicyId"); // OK
		xacmlModelElement.put("PolicySet", "xmlns,xmlns:ns2,xmlns:xacml,PolicyCombiningAlgId"); // OK
		xacmlModelElement.put("Policy", "RuleCombiningAlgId,PolicyId"); // OK
		xacmlModelElement.put("Match", "MatchId"); // OK
		xacmlModelElement.put("Rule", "Effect,RuleId"); // RuleID not defined
		xacmlModelElement.put("Apply", "FunctionId"); // OK
		xacmlModelElement.put("AttributeValue", "DataType"); //OK
		xacmlModelElement.put("AttributeDesignator", "MustBePresent,DataType,AttributeId,Category"); // OK   
	}
	public void xacmlClassSpecs(){
		xacmlModelClass.put("Match", "AttributeValue,AttributeDesignator");
		xacmlModelClass.put("Apply", "AttributeValue");
	}
	public void valueMapping(){
		valueTable.put("PolicySet:PolicyCombiningAlgId", "PolicySet:urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm");
		valueTable.put("Policy:RuleCombiningAlgId", "Policy:urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm");
		valueTable.put("", "");
		valueTable.put("Resource", "Target");
		valueTable.put("Rule", "Rule");
	}
	public void contextValueMapping(){
		
	    mapTable.put("Match:MatchId:Subject", "urn:sun:opensso:entitlement:json-subject-match");
	    mapTable.put("Match:MatchId:URL", "urn:sun:opensso:entitlement:resource-match:application:$appName");
	    mapTable.put("Match:MatchId:Action", "urn:sun:opensso:entitlement:action-match:application:$appName");
	     
	    mapTable.put("AttributeValue:DataType:Authentication", "urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.AuthenticatedUsers");
    	mapTable.put("Match:MatchId:Authentication", "urn:sun:opensso:entitlement:json-subject-match");
    	mapTable.put("Apply:FunctionId:Authentication", "urn:sun:opensso:entitlement:json-subject-and-condiiton-satisfied");
    	
    	
        
            
	    mapTable.put("AttributeValue:DataType:Subject", "urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.IdentitySubject");
	    mapTable.put("AttributeValue:DataType:URL", "http://www.w3.org/2001/XMLSchema#string");
	    mapTable.put("AttributeValue:DataType:Action", "http://www.w3.org/2001/XMLSchema#string");
	    mapTable.put("AttributeValue:DataType:Application", "http://www.w3.org/2001/XMLSchema#string");
	    
	    mapTable.put("AttributeDesignator:DataType:Subject", "urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.IdentitySubject");
	    mapTable.put("AttributeDesignator:DataType:URL", "http://www.w3.org/2001/XMLSchema#string");
	    mapTable.put("AttributeDesignator:DataType:Action", "http://www.w3.org/2001/XMLSchema#string");
	    mapTable.put("AttributeDesignator:DataType:Application", "http://www.w3.org/2001/XMLSchema#string");
	    mapTable.put("AttributeDesignator:DataType:Authentication", "urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.AuthenticatedUsers");
	    
	    
	    mapTable.put("AttributeDesignator:AttributeId:Subject", "urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.IdentitySubject");
	    mapTable.put("AttributeDesignator:AttributeId:URL", "http://www.w3.org/2001/XMLSchema#string");
	    mapTable.put("AttributeDesignator:AttributeId:Action", "http://www.w3.org/2001/XMLSchema#string");
	    mapTable.put("AttributeDesignator:AttributeId:Application", "");
	    mapTable.put("AttributeDesignator:AttributeId:Authentication", "urn:sun:opensso:entitlement:json-subject");
	    
	    
	    mapTable.put("AttributeDesignator:Category:Subject", "urn:sun:opensso:entitlement:json-subject");
	    mapTable.put("AttributeDesignator:Category:URL", "urn:oasis:names:tc:xacml:1.0:resource:resource-id");
	    mapTable.put("AttributeDesignator:Category:Action", "urn:oasis:names:tc:xacml:1.0:action:action-id");
	    mapTable.put("AttributeDesignator:Category:Application", "urn:sun:opensso:application-id");
	    mapTable.put("AttributeDesignator:Category:Authentication", "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
	    
	    mapTable.put("AttributeValue:privilegeComponent:Subject", "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
	    mapTable.put("AttributeValue:privilegeComponent:URL", "urn:oasis:names:tc:xacml:3.0:attribute-category:resource");
	    mapTable.put("AttributeValue:privilegeComponent:Action", "urn:oasis:names:tc:xacml:3.0:attribute-category:action");
	    mapTable.put("AttributeValue:privilegeComponent:Application", "urn:sun:opensso:application-category");
	   
	    mapTable.put("AttributeDesignator:MustBePresent:Subject", "true");
	    mapTable.put("AttributeDesignator:MustBePresent:Application", "false");
	    mapTable.put("AttributeDesignator:MustBePresent:Action", "true");
	    mapTable.put("AttributeDesignator:MustBePresent:URL", "true");
	    
	    mapTable.put("Apply:FunctionId:Rule", "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
	    mapTable.put("Apply:FunctionId:Rule", "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
	    mapTable.put("Apply:FunctionId:Rule", "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject");
	    
	}
	public void subjecttypeMapping(){
		datatypeSubject.put("IdentitySubject", "urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.IdentitySubject");
		datatypeSubject.put("Authenticated", "urn:sun:opensso:entitlement:json-subject-type:org.forgerock.openam.entitlement.conditions.subject.AuthenticatedUsers");
		datatypeSubject.put("NoSubject", "urn:sun:opensso:entitlement:json-subject-type:com.sun.identity.entitlement.NoSubject");
	}
	public void individualconditiontypeMapping(){
		individualdatatypeCondition.put("IPv4Condition", "urn:sun:opensso:entitlement:json-condition-type:org.forgerock.openam.entitlement.conditions.environment.IPv4Condition");
		individualdatatypeCondition.put("NeoUniversalCondition", "urn:sun:opensso:entitlement:json-condition-type:com.nulli.openam.plugins.NeoUniversalCondition");
		individualdatatypeCondition.put("AuthenticateToRealmCondition", "urn:sun:opensso:entitlement:json-condition-type:org.forgerock.openam.entitlement.conditions.environment.AuthenticateToRealmCondition");
		individualdatatypeCondition.put("LDAPFilterCondition", "urn:sun:opensso:entitlement:json-condition-type:org.forgerock.openam.entitlement.conditions.environment.LDAPFilterCondition");
		individualdatatypeCondition.put("ANDCondition","urn:sun:opensso:entitlement:json-condition-type:com.sun.identity.entitlement.AndCondition");
		individualdatatypeCondition.put("NOTCondition","urn:sun:opensso:entitlement:json-condition-type:com.sun.identity.entitlement.NotCondition");	
		individualdatatypeCondition.put("ORCondition","urn:sun:opensso:entitlement:json-condition-type:com.sun.identity.entitlement.OrCondition");	
	}
	public void compositeconditiontypeMapping(){
		//datatypeCondition.put("IPv4Condition", "urn:sun:opensso:entitlement:json-condition-type:org.forgerock.openam.entitlement.conditions.environment.IPv4Condition");
		compositedatatypeCondition.put("IPv4Condition", "org.forgerock.openam.entitlement.conditions.environment.IPv4Condition");
		//datatypeCondition.put("NeoUniversalCondition", "urn:sun:opensso:entitlement:json-condition-type:com.nulli.openam.plugins.NeoUniversalCondition");
		//datatypeCondition.put("AuthenticateToRealmCondition", "urn:sun:opensso:entitlement:json-condition-type:org.forgerock.openam.entitlement.conditions.environment.AuthenticateToRealmCondition");
		//datatypeCondition.put("LDAPFilterCondition", "urn:sun:opensso:entitlement:json-condition-type:org.forgerock.openam.entitlement.conditions.environment.LDAPFilterCondition");
		compositedatatypeCondition.put("LDAPFilterCondition", "org.forgerock.openam.entitlement.conditions.environment.LDAPFilterCondition");
		compositedatatypeCondition.put("NOTCondition","com.sun.identity.entitlement.NotCondition");
		compositedatatypeCondition.put("ORCondition","com.sun.identity.entitlement.OrCondition");
		compositedatatypeCondition.put("ANDCondition","com.sun.identity.entitlement.AndCondition");
		compositedatatypeCondition.put("TemporalCondition","org.forgerock.openam.entitlement.conditions.environment.SimpleTimeCondition");
	}
	public void metadataAttributesMapping(){
		metadataAttributes.put("applicationName","sun.opensso.entitlement.applicationName");
		metadataAttributes.put("createdBy","sun.opensso.privilege.createdBy");
		metadataAttributes.put("creationDate","sun.opensso.privilege.creationDate");
		metadataAttributes.put("modifiedBy","sun.opensso.privilege.modifiedBy");
		metadataAttributes.put("modifiedDate","sun.opensso.privilege.modifiedDate");	
	}
}
