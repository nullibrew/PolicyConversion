import java.io.File;
import java.io.*;
import java.io.PrintWriter;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;
import java.util.*;
public class XMLParserR1 {
   Map<String, String> days = new HashMap<String, String>();
   public XMLParserR1(String inputPolicyFile, String fileName){
	  days.put("1", "Sun"); 
	  days.put("2", "Mon"); 
	  days.put("3", "Tues"); 
	  days.put("4", "Wed"); 
	  days.put("5", "Thurs"); 
	  days.put("6", "Fri"); 
	  days.put("7", "Satur"); 
      try {	
    	 Hashtable<String, String> hosts = new Hashtable<String, String>();
    	 Hashtable<String, String> authScheme = new Hashtable<String, String>();
    	 Hashtable<String, String> authzScheme = new Hashtable<String, String>();
    	 PrintWriter writer = new PrintWriter(fileName, "UTF-8");
    	 File inputFile=null;
    	 inputFile = new File(inputPolicyFile);
         DocumentBuilderFactory dbFactory 
            = DocumentBuilderFactory.newInstance();
         DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
         Document doc=null;
         try {
        	 doc = dBuilder.parse(inputFile);
         } 
    	 catch (FileNotFoundException fe) {
    		 System.out.println("Input Policy File Not Found");
    		 System.exit(1);
    	 }    
         doc.getDocumentElement().normalize();
         // Find the resource types and action types 
         NodeList resTypeList = doc.getElementsByTagName("resource-type");
         NodeList HIList = doc.getElementsByTagName("host-identifier");
         for (int HICounter = 0; HICounter < HIList .getLength(); HICounter++) {
             Node HINode = HIList .item(HICounter);
             String hostName = null;
             String combinedHostString="";
             if (HINode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) HINode;
                hostName = eElement.getAttribute("id");
                NodeList hostList = eElement.getElementsByTagName("host");   
                for (int hostCounter = 0; hostCounter < hostList .getLength(); hostCounter++) {
                	Node hostNode = hostList .item(hostCounter);
                	if (hostNode.getNodeType() == Node.ELEMENT_NODE) {
                		Element hostElement = (Element) hostNode;
                		String fullHost=hostElement.getAttribute("name")+":"+hostElement.getAttribute("port");
                		if (combinedHostString.equals("")) {
                			combinedHostString = fullHost;
                		}
                		else {
                			combinedHostString = combinedHostString + "+" + fullHost;
                		}
                    }
                }
             }
             hosts.put(hostName, combinedHostString);
         }
         NodeList authzPolicyList = doc.getElementsByTagName("authz-policy");
         for (int authzPolCounter = 0; authzPolCounter < authzPolicyList.getLength(); authzPolCounter++) {
             Node authzPolNode = authzPolicyList .item(authzPolCounter);
             String polName = null;
             String combinedHostString="";
             if (authzPolNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) authzPolNode;
                polName = eElement.getAttribute("id");
                NodeList resourceList = eElement.getElementsByTagName("resource");   
                for (int resourceCounter = 0; resourceCounter < resourceList .getLength(); resourceCounter++) {
                	Node resourceNode = resourceList.item(resourceCounter);
                	if (resourceNode.getNodeType() == Node.ELEMENT_NODE) {
                		Element resourceElement = (Element) resourceNode;
                		authzScheme.put(resourceElement.getAttribute("id"), polName);
                    }
                }
             }
         }
         NodeList authPolicyList = doc.getElementsByTagName("authn-policy");
         for (int authPolCounter = 0; authPolCounter < authPolicyList.getLength(); authPolCounter++) {
             Node authPolNode = authPolicyList .item(authPolCounter);
             String polName = null;
             String combinedHostString="";
             if (authPolNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) authPolNode;
                polName = eElement.getAttribute("id");
                NodeList resourceList = eElement.getElementsByTagName("resource");   
                for (int resourceCounter = 0; resourceCounter < resourceList .getLength(); resourceCounter++) {
                	Node resourceNode = resourceList.item(resourceCounter);
                	if (resourceNode.getNodeType() == Node.ELEMENT_NODE) {
                		Element resourceElement = (Element) resourceNode;
                		authScheme.put(resourceElement.getAttribute("id"), polName);
                    }
                }
             }
         }
         
         Vector<String> opVec = new Vector();
         writer.println("Resource Types:");
         writer.println("- type: HTTP");
         writer.println("  operation:");
         for (int resTypeCounter = 0; resTypeCounter < resTypeList .getLength(); resTypeCounter++) {
            Node nNode = resTypeList .item(resTypeCounter);
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {
               Element eElement = (Element) nNode;
               if (eElement.getAttribute("name").equals("HTTP")) {   	   
            	   NodeList opList = eElement.getElementsByTagName("operation");
            	   for (int opTypeCounter = 0; opTypeCounter < opList .getLength(); opTypeCounter++) {
                       Node opNode = opList .item(opTypeCounter);
                       if (opNode.getNodeType() == Node.ELEMENT_NODE) {
                    	   Element opElement = (Element) opNode;
                    	   opVec.addElement(opElement.getAttribute("name"));
                       }
                   }
               }
            }
         }
         for (int i=0;i<opVec.size();i++){
        	 writer.println("   - "+opVec.elementAt(i));
         }
         writer.println("\n");
         // Now get the application domains
         writer.println("Application Domains:");
         NodeList domainList = doc.getElementsByTagName("application-domain");
         for (int domainCounter = 0; domainCounter < domainList .getLength(); domainCounter++) {
            Node domainNode = domainList.item(domainCounter);
            if (domainNode.getNodeType() == Node.ELEMENT_NODE) {
               Element eElement = (Element) domainNode;
               writer.println(" - domainname: "+eElement.getAttribute("name"));
               writer.println("   description: "+eElement.getAttribute("description"));
               writer.println("   resource-list:");
              
               
               NodeList resourceList = eElement.getElementsByTagName("resources");  
               NodeList rs = eElement.getElementsByTagName("resource");
               
               for (int resourceCounter = 0; resourceCounter < rs.getLength(); resourceCounter++) {
            	   Node resourceNode = rs.item(resourceCounter);
            	   Element resourceElement = (Element) resourceNode; 
            	   if (resourceElement.getParentNode().equals(resourceList.item(0))) {
            		    
            	   		String hostIdentifier = resourceElement.getAttribute("hostidentifier");
            	   		String optionalDesc = "";
            	   		String listofURL = hosts.get(hostIdentifier);
            	   		String delims = "\\+";
            	   		String [] urlArray = {""};
   	    		   		if (hosts.get(hostIdentifier)!=null) {
   	    		   			urlArray = hosts.get(hostIdentifier).split(delims);
   	    		   		}
   	    		   		for (int i=0;i<urlArray.length;i++) { 
   	    			   		String fullURL = urlArray[i]+resourceElement.getElementsByTagName("resource-url").item(0).getTextContent();
   	    			   		optionalDesc = resourceElement.getAttribute("description");
   	    			   		writer.println("    - id: "+resourceElement.getAttribute("id")+"-"+i);
   	    			   		writer.println("      description: "+optionalDesc);
   	    			   		writer.println("      url: "+fullURL);
   	    			   		NodeList opList = resourceElement.getElementsByTagName("operations");
   	    			   		writer.println("      protectiontype: "+resourceElement.getElementsByTagName("protection-level").item(0).getTextContent());
   	    			   		writer.println("      operations:");
	    			   		if (opList.getLength()==0) {
	    			   			for (int opC=0;opC<opVec.size();opC++){
	    			   		writer.println("       - name: "+opVec.elementAt(opC));
	    			   			}
	    			   		}
   	    			   		writer.println("      authentication: "+authScheme.get(resourceElement.getAttribute("id")));
   	    			   		writer.println("      authorization: "+authzScheme.get(resourceElement.getAttribute("id")));
   	    			   		
   	    		   		}
   	    		   }
               	}
               
            }
         }
         writer.println("Authentication Policies:");
         NodeList authnPolList = doc.getElementsByTagName("authn-policy");
         for (int polCounter = 0; polCounter < authnPolList .getLength(); polCounter++) {
            Node polNode = authnPolList.item(polCounter);
            if (polNode.getNodeType() == Node.ELEMENT_NODE) {
               Element eElement = (Element) polNode;
               
               writer.println(" - name: "+eElement.getAttribute("name"));
               writer.println("   description: "+eElement.getAttribute("description"));
               writer.println("   id: "+eElement.getAttribute("id"));
               
               NodeList schemeList = eElement.getElementsByTagName("authn-scheme");
               for (int schemeCounter = 0; schemeCounter < schemeList .getLength(); schemeCounter++) {
            	   Node schemeNode = schemeList .item(schemeCounter);
            	   Element schemeElement = (Element) schemeNode;
                   writer.println("   schemeid: "+schemeElement.getAttribute("id"));
               }
            }
         } 
         writer.println("Authorization Policies:");
         NodeList authzPolList = doc.getElementsByTagName("authz-policy");
         for (int polCounter = 0; polCounter < authzPolList .getLength(); polCounter++) {
             Node polNode = authzPolList.item(polCounter);
             if (polNode.getNodeType() == Node.ELEMENT_NODE) {
                Element eElement = (Element) polNode;
                
                writer.println(" - name: "+eElement.getAttribute("name"));
                writer.println("   id: "+eElement.getAttribute("id"));
                NodeList constList = eElement.getElementsByTagName("constraint");
                
                writer.println("   constraints:");
                for (int constCounter = 0; constCounter < constList .getLength(); constCounter++) {
             	   Node constNode = constList .item(constCounter);
             	   Element constElement = (Element) constNode;
             	   String permitclass = constElement.getAttribute("class"); 
                   writer.println("    - permittype: "+constElement.getAttribute("type"));
                   writer.println("      name: "+constElement.getAttribute("name"));
                   writer.println("      combiningoperator: "+"AND");
                   writer.println("      conditions:");
                   if (constElement.getAttribute("class").equals("IDENTITY")) {
                	   // Get the entities list        
                       writer.println("       - name: "+constElement.getAttribute("name"));
                       writer.println("         conditiontype: "+permitclass);
                       writer.println("         Entities:");
                	  
                	   NodeList idList = constElement.getElementsByTagName("identity");
 
                	   for (int idCounter = 0; idCounter < idList .getLength(); idCounter++) {
                     	   Node idNode = idList .item(idCounter);
                     	   Element idElement = (Element) idNode;
                           
                     	   writer.println("          - type: "+idElement.getAttribute("type"));
                     	   writer.println("            name: "+idElement.getAttribute("identifier"));
                	   }
                   }
                   else if (constElement.getAttribute("class").equals("IP4_RANGE")) {
                	   NodeList ipList = constElement.getElementsByTagName("ip4-range");
                	   writer.println("       - name: "+constElement.getAttribute("name"));
                       writer.println("         conditiontype: "+permitclass);
                	   for (int ipCounter = 0; ipCounter < ipList .getLength(); ipCounter++) {
                     	   Node ipNode = ipList .item(ipCounter);
                     	   Element ipElement = (Element) ipNode;
                     	   Node fromNode = ipElement.getElementsByTagName("from-ip4").item(0);
                     	   Node toNode = ipElement.getElementsByTagName("to-ip4").item(0);
                     	   writer.println("         IP Start: "+((Element)fromNode).getAttribute("inet-addr"));
                     	   writer.println("         IP End : "+((Element)toNode).getAttribute("inet-addr"));
                	   }  
                   }
                   else if (constElement.getAttribute("class").equals("TEMPORAL")) {
                	   NodeList temporalList = constElement.getElementsByTagName("temporal");
                	   for (int temporalCounter = 0; temporalCounter < temporalList .getLength(); temporalCounter++) {
                     	   Node temporalNode = temporalList .item(temporalCounter);
                     	   Element temporalElement = (Element) temporalNode;
                     	   Node timeofdayNode = temporalElement.getElementsByTagName("time-of-day").item(0);
                     	   Node dayofweekNode = temporalElement.getElementsByTagName("day-of-week").item(0);
                     	   Element timeofdayElement = (Element) timeofdayNode;
                     	   Element dayofweekElement = (Element) dayofweekNode;
                     	   NodeList dayList = dayofweekElement.getElementsByTagName("day");
                     	   String startDay="";
                     	   String endDay="";
                     	   for (int dayCounter = 0; dayCounter < dayList .getLength(); dayCounter++) {
                     		   if (dayCounter==0) {
                     			   startDay = dayofweekElement.getElementsByTagName("day").item(0).getTextContent();
                     		   }
                     		   else if (dayCounter==1) {
                     			   endDay = dayofweekElement.getElementsByTagName("day").item(1).getTextContent();
                     		   }
                     	   }
                           writer.println("         Start Time: "+((Element)timeofdayElement.getElementsByTagName("begin-time").item(0)).getAttribute("seconds"));
                           writer.println("         End Time: "+((Element)timeofdayElement.getElementsByTagName("end-time").item(0)).getAttribute("seconds"));
                           writer.println("         Start Day: "+days.get(startDay));
                           writer.println("         End Day: "+days.get(endDay));
                	   }
                   }
                }
             }
          }
          writer.println("Authentication Schemes:");
          NodeList schemes = doc.getElementsByTagName("authn-schemes");
          NodeList schemePolList = doc.getElementsByTagName("authn-scheme");
          for (int schemeCounter = 0; schemeCounter < schemePolList .getLength(); schemeCounter++) {
            Node schemeNode = schemePolList.item(schemeCounter);
            Element schemeElement = (Element) schemeNode; 
            if (schemeElement.getParentNode().equals(schemes.item(0))) {
               Element eElement = (Element) schemeNode;
               writer.println(" - type: "+eElement.getAttribute("type"));
               writer.println("   name: "+eElement.getAttribute("name"));
               writer.println("   id: "+eElement.getAttribute("id"));
               writer.println("   description: "+eElement.getAttribute("description"));
               writer.println("   auth-level: "+eElement.getAttribute("auth-level"));
              
               writer.println("   challenge-redirect-url: "+eElement.getElementsByTagName("challenge-redirect-url").item(0).getTextContent());
               writer.println("   challenge-mechanism: "+eElement.getElementsByTagName("challenge-mechanism").item(0).getTextContent());
               writer.println("   auth-level: "+eElement.getAttribute("auth-level"));
               NodeList moduleList = eElement.getElementsByTagName("authn-module");
               for (int moduleCounter = 0; moduleCounter < moduleList .getLength(); moduleCounter++) {
            	   Node moduleNode = moduleList .item(moduleCounter);
            	   Element moduleElement = (Element) moduleNode;
                   writer.println("   auth-modulename: "+moduleElement.getAttribute("name"));
               }
            }
          } 
          writer.close();
      } catch (Exception e) {
         e.printStackTrace();
      }
   }
}