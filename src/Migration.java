
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

import java.io.FileNotFoundException;
import java.util.Vector;


import PolicyModel.Policy;
import PolicyModel.PolicySet;
import PolicyModel.Resource;
import PolicyModel.Action;
import PolicyModel.Rule;
import PolicyModel.IdentityCondition;
import PolicyModel.EnvironmentCondition;
public class Migration {

	public static void main(String[] args) {
		/* Possible argument list
		   1. OAM Version
		   2. OpenAM Version
		   3. Input XML policyfile (OAM)
		   4. Output XACML filename  
		*/
		String openamVersion="";
		String oamVersion;
		String inputPolicyFile;
		String outputPolicyFile;
		ArgumentParser argparser = ArgumentParsers.newArgumentParser("policy conversion")
                .description("Converting access policies netween OAM and OpenAM"); 
		argparser.addArgument("--oamVersion")
        .choices("11gr1","11gr2")
        .type(String.class)
        .help("OAM Version Number: Options: 11gr1, 11gr2");
		argparser.addArgument("--openamVersion")
        .choices("12","13")
        .type(String.class)

        .help("Target OpenAM Version: Options: 12, 13");
		argparser.addArgument("-i","--input")
        .type(String.class)

        .help("OAM policies:, e.g., input_policy.xml");
		argparser.addArgument("-o","--output")
        .setDefault("policy_output.xml")
        .type(String.class)

        .help("XACML Output destination:, e.g., policy_output.xml");
		Namespace ns = null;
		try {
	            ns = argparser.parseArgs(args);
	        } catch (ArgumentParserException e) {
	            argparser.handleError(e);
	            System.exit(1);
	    }
		//System.out.println(ns);  
		oamVersion = ns.getString("oamVersion");
		openamVersion = ns.getString("openamVersion");
		inputPolicyFile = ns.getString("input");   
        outputPolicyFile = ns.getString("output");
		ModelPopulatorOAM mp=null;

		if (oamVersion.equals("11gr2")) {
			String fileName = "oamPolicy_R2.yml";
			XMLParserR2 parser = new XMLParserR2(inputPolicyFile, fileName);
			mp=new ModelPopulatorOAM(fileName);
		}
		else if (oamVersion.equals("11gr1")) {
			String fileName = "oamPolicy_R1.yml";
			XMLParserR1 parser = new XMLParserR1(inputPolicyFile, fileName);
			mp=new ModelPopulatorOAM(fileName);
		}
		if (openamVersion.equals("12")) {
			XACMLCreatorv12 xc= new XACMLCreatorv12(mp, outputPolicyFile);
		}
		else {
			XACMLCreatorv13 xc= new XACMLCreatorv13(mp, outputPolicyFile);
		}
	}

}
