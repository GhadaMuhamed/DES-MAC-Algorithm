import javax.crypto.KeyGenerator;

import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class MAC {

	private String opad,ipad,Keyplus;
	private static Integer b;


	public MAC(String key){

		b=512;  // since we are using sha1

		// left pad key, ipad and opad with zeros
		Keyplus=String.format("%1$" + b + "s", key).replace(' ', '0');

		//repeat b/8 time so that ipad and opad length becomes equal b bits
		ipad ="00110110";
		opad="01011100";

		for (int i = 1; i <(b/8); i++) {
			ipad += "00110110";
			opad+="01011100";
		}

	}

	public String getHMAC(String text) throws NoSuchAlgorithmException{

		byte[] tbytes=text.getBytes();
		String binary = Tobinary(tbytes);
		//System.out.println (binary);
		String Si=	XOR(Keyplus,ipad);
		String S0=XOR(Keyplus,opad);

		//Check if the text can be divided to l blocks of size b bits 
		if(binary.length()%b !=0){
			if(binary.length()<b){
				binary=String.format("%1$" + b + "s", binary).replace(' ', '0');
			}
			else{
				int x=binary.length()-(binary.length()%b);
				String z =binary.substring(x, binary.length());
				binary=binary.substring(0,x)+(String.format("%1$" + b + "s", z).replace(' ', '0'));
			}
		}

		String Temp1=Si+binary; //append Si to the message
		Temp1 = new String(new BigInteger(Temp1, 2).toByteArray());

		// ****************** first Hash ******************  

		MessageDigest md = MessageDigest.getInstance("SHA-224");
		md.update(Temp1.getBytes());
		byte[] digest = md.digest();
		//String H=new BigInteger(1,digest).toString();
		String H=Tobinary(digest);
		H=String.format("%1$" + b + "s", H).replace(' ', '0');

		// ****************** second Hash ****************** 
		String Temp2 = S0+H; //append S0 to the hash
		md.reset();
		md.update(Temp2.getBytes());
		byte[] mDigest = md.digest();
		BigInteger no = new BigInteger(1, mDigest);
		String MD = no.toString(16);
		while (MD.length() < 32) {
			MD = "0" + MD;
		}




		return MD;
	}

	private static String XOR(String d1,String d2){
		BigInteger k=new BigInteger('1'+d1,2);
		BigInteger p=new BigInteger(d2,2);

		BigInteger R = k.xor(p);
		return (R.toString(2)).substring(1,b+1);
	}

	private static String Tobinary(byte[] s){

		String result="";
		int i=0;
		while(i<s.length){
			String s1 = String.format("%8s", Integer.toBinaryString(s[i] & 0xFF)).replace(' ', '0');
			result+=s1;
			i++;
		}

		return result;

	}

}




