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
	      String secretKey=Tobinary(kbytes);
	      
	      try{    
	           FileWriter fw=new FileWriter("secretKey.txt");    
	           fw.write(secretKey);    
	           fw.close();    
	          }catch(Exception e){System.out.println(e);}    
	             
	        
	   }

	 private static String Tobinary(byte[] s){
		 
		Random rand = new Random();
		String result="";
		int i=0;
		
			while(i<s.length){
				String s1 = String.format("%8s", Integer.toBinaryString(s[i] & 0xFF)).replace(' ', '0');
				result+=s1;
				i++;
			}

			int n = rand.nextInt(Math.min(512,result.length()));  // 512 since we are using shA-224
			return result.substring(0,n);
			
		}
			
}
