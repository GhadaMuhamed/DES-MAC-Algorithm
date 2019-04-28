import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.FileWriter;  
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;

public class SecretKey {
	
	public void run() throws Exception{
	      KeyGenerator keyGen = KeyGenerator.getInstance("DES");
	      SecureRandom secRandom = new SecureRandom();
	      keyGen.init(secRandom);
	      Key key = keyGen.generateKey();
	      String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
	      byte[] kbytes=encodedKey.getBytes();
	     
	      
	      try{    
	           FileWriter fw=new FileWriter("secretKey.txt");    
	           fw.write(encodedKey);    
	           fw.close();    
	          }catch(Exception e){System.out.println(e);}  
	      
	 	   }			
}

