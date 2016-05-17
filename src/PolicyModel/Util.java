package PolicyModel;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Member;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;


import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;

/**
 * Contains various unorganized static utility methods used across Cayenne.
 * 
 * @author Andrei Adamchik
 */
public class Util {
  /**
   * Encodes a string so that it can be used as an attribute value in an XML document.
   * Will do conversion of the greater/less signs, quotes and ampersands.
   */
  public static String encodeXmlAttribute(String str) {
      if (str == null)
          return null;

      int len = str.length();
      if (len == 0)
          return str;

      StringBuffer encoded = new StringBuffer();
      for (int i = 0; i < len; i++) {
          char c = str.charAt(i);
          if (c == '<')
              encoded.append("&lt;");
          else if (c == '\"')
              encoded.append("&quot;");
          else if (c == '>')
              encoded.append("&gt;");
          else if (c == '\'')
              encoded.append("&apos;");
          else if (c == '&')
              encoded.append("&amp;");
          else
              encoded.append(c);
      }

      return encoded.toString();
  }
}