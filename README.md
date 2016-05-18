# PolicyConversion
A tool to convert Oracle Access Manager policies to OpenAM policies
Summary

The PolicyConversion tool reads policies exported from Oracle Access Manager (OAM) and converts them to XACML 3.0 format, which can then be imported to an OpenAM instance. The tool can be particularly useful for organizations who are planning to switch from OAM to OpenAM and wish to automate the migration process. 

##Conversion Process
OAM provides a logical container for resources or sets of resources, and the associated policies that dictate who can access specific protected resources. OAM differ in terms of storing of policies.  Versions prior to 11g, OAM used to store the policies on the LDAP server. However, since 11g, Database is being used for that purpose. OAM 11g provides the functionality of exporting the policies through WLST scripting tool. No such mechanism exist for the prior versions. The process of conversation follows the following high level steps:

 - Export the policies to an XML file.
 - The policies are parsed from the XML file and written to a YAML policy template.
 - The policies are read and parsed from the YAML instance and converted to a set of Java classes. 
 - The Java classes are translated to various XACML 3.0 policy elements and combined together. 
 
Although the tool is designed for converting policies between OAM and OpenAM, the modular design of the workflow will allow to target any phase of the workflow. For instance, it is possible to use the YAML template to create the policy specification in YAML and generating the OpenAM compliant XACML policies.  
##Feature/Version
Figure 1 indicates the products versions that are supported with the current tool. The solid line between the components indicates that the line that is supported by the current version of the tool while the dotted line indicates the future project. The following versions are supported:
 - OAM 11gR1
 - OAM 11gR2
 - OpenAM 12.0.0
 - OpenAM 13.0.0

##Limitations
The current version of the tool has the following limitations. We are actively work on these issues: 
The tool currently is not able to translate an IP based or Temporal restrictions for OAM 11gR1. However, it is able to do it for the 11gR2 version. 
OAM 11gR2 supports policies based on the LDAP attribute of the user/group. Such policies have not been tested for this tool. 

##Ongoing Work:
The future work will address the current limitations of the tool. In addition, support for 10g version of OAM to be included in the future versions. 


