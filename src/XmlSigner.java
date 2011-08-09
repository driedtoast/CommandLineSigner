import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Collections;

import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class XmlSigner {
	
	public static String signDocument(Document doc, KeyPair kp)
            throws GeneralSecurityException, MarshalException, XMLSignatureException, TransformerException {
        final Element element = doc.getDocumentElement();
        String id = element.getAttribute("ID");
        if (null != id) {
            id = "#" + id;
        }
        return createEnvelopedSignature(doc, kp, element, id);
    }

     public static String createEnvelopedSignature(Document doc, KeyPair kp, Element elementToSign, String refUri)
            throws GeneralSecurityException, MarshalException, XMLSignatureException, TransformerException {
                XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference(refUri,
                                         fac.newDigestMethod(DigestMethod.SHA1, null),
                                         Collections.singletonList(fac.newTransform
                                                 (Transform.ENVELOPED, (TransformParameterSpec) null)),
                                         null, null);

        SignedInfo si = fac.newSignedInfo
                (fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                 fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                 Collections.singletonList(ref));
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));

        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), elementToSign);
        dsc.putNamespacePrefix(XMLSignature.XMLNS, "ds"); //  http://www.w3.org/2000/09/xmldsig#
        javax.xml.crypto.dsig.XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);
        return serializeDom(doc);
    }
	
     public static String serializeDom(Document doc) throws TransformerException {
	     StringWriter writer = new StringWriter();
	     TransformerFactory tf = TransformerFactory.newInstance();
	     Transformer trans = tf.newTransformer();
	     trans.transform(new DOMSource(doc), new StreamResult(writer));
	     // serialized dom
	     return writer.toString();
     }
     
     /**
      * Parse the dom from bytes
      */
     public static Document createDom(byte[] domStr) throws SAXException, IOException, ParserConfigurationException  {
         DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
         dbf.setNamespaceAware(true);
         dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
         dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
         dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
         dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

         DocumentBuilder db = dbf.newDocumentBuilder();
         return db.parse(new InputSource( new ByteArrayInputStream(domStr)));
     }
     
     /**
      * Load the keypair from file
      */
     public static KeyPair loadKeyPair(String filename)  throws IOException {
    	 BufferedReader br = new BufferedReader(new FileReader(filename));
    	 Security.addProvider(new BouncyCastleProvider());
    	 return  (KeyPair)new PEMReader(br).readObject();
     }
     
	public static void main(String[] args) {
	   String keyfile = args[0];
	   String base64Xml = args[1];
	   try {
		   KeyPair kp = loadKeyPair(keyfile);
		   Document doc = createDom(Base64.decode(base64Xml.getBytes("UTF-8")));
		   String xml = signDocument(doc, kp);
		   System.out.println(new String(Base64.encode(xml.getBytes("UTF-8")),"UTF-8"));
		   
	   } catch (Exception e) {
		   e.printStackTrace();
		   System.out.println("failed");
	   }
	}
}
