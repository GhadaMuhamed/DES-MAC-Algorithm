import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Receiver {
    DES des = new DES();
    int s = 8;
    static final String base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
       Long key, IV;
    void getKey() throws Exception {
        Scanner sc = new Scanner(new File("DesKey.txt"));
        key = sc.nextLong();
        IV = sc.nextLong();
    }
    public Receiver() throws Exception {
        getKey();
    }


    private static String readFromFile(String filename) throws Exception {
        Scanner sc = new Scanner(new File(filename));
        return sc.nextLine();
    }


    public void receive() throws Exception {

        //String msg = (String) readFromFile("SentMsg.txt");
        //Integer mode = Character.getNumericValue(msg.charAt(0));
        int mode = Integer.valueOf(readFromFile("mode.txt"));
        String msg = readFromFile("sentMsg.txt");
        if (mode == 1)
            receiveECB(msg);
        else if (mode == 2)
            receiveCBC(msg);
        else if (mode == 3)
            receiveCFB(msg);
        else if (mode == 4)
            receiveOFB(msg);
        else receiveCnt(msg);
    }

   static String findTwoscomplement(String s)
   {
       StringBuffer str = new StringBuffer(s);
       int n = str.length();

       // Traverse the string to get first '1' from
       // the last of string
       int i;
       for (i = n-1 ; i >= 0 ; i--)
           if (str.charAt(i) == '1')
               break;

       // If there exists no '1' concat 1 at the
       // starting of string
       if (i == -1)
           return "1" + str;

       // Continue traversal after the position of
       // first '1'
       for (int k = i-1 ; k >= 0; k--)
       {
           //Just flip the values
           if (str.charAt(k) == '1')
               str.replace(k, k+1, "0");
           else
               str.replace(k, k+1, "1");
       }

       // return the modified string
       return str.toString();
   }
    Long Base64ToLong(String s){
        String res = "";
       for (int i=0;i<s.length();++i){

            Integer decode = base64_chars.indexOf(s.charAt(i));
            res += String.format("%6s", Integer.toBinaryString(decode & 0xFF)).replace(' ', '0');
       }
       if (res.charAt(2) == '1')
          return Long.valueOf(findTwoscomplement(res.substring(2)),2) * -1;
      return Long.valueOf(res.substring(3),2);
   }

   List<Byte> longtoBytes(Long num){
        List<Byte> res = new ArrayList<>();
        String s = Long.toBinaryString(num);
        String z = "";
        while (s.length()+z.length()<63)
            z+='0';
        String bin = z+s;
        String tmp = "";
        int cnt=0;
        for (int i=0;i<bin.length();++i){
            tmp += bin.charAt(i);
            if (tmp.length() == 7){
                Byte charNum = Byte.valueOf(tmp,2);
                tmp = "";
                if (charNum < 32)
                    continue;
                res.add(charNum);
            }
        }
        return res;
   }

   public String bytesToString(List<Byte> ls){
      byte[] bytes = new byte[ls.size()];
      for (int i=0;i<ls.size();++i)
          bytes[i] = ls.get(i);
       return new String(bytes);
   }

    public Long HexToLong(String s){
       return Long.valueOf(s,16);
    }

    public void receiveOFB(String msg) throws Exception {
        String tmp = "";
        Long nonce = IV;
        PrintWriter pw = new PrintWriter("receivedMsg.txt");
        for (int i=0;i<msg.length();++i){
            tmp+= msg.charAt(i);
            if (tmp.length() == 11){
                Long toBeDec = Base64ToLong(tmp);
                Long num = des.encrypt(nonce, key);
                nonce = num;
                num ^= toBeDec;
                List<Byte> asciiBytes = longtoBytes(num);
                pw.print(bytesToString(asciiBytes));
                tmp = "";
            }
        }
        pw.close();
    }
    public void receiveCnt(String msg) throws Exception {
        String tmp = "";
        PrintWriter pw = new PrintWriter("receivedMsg.txt");
        Long counter = IV;
        BigInteger bg = new BigInteger("18446744073709551615");
        for (int i=0;i<msg.length();++i){
            tmp+= msg.charAt(i);
            if (tmp.length() == 11){
                Long toBeDec = Base64ToLong(tmp);
                Long num = des.encrypt(counter, key);
                if (bg.equals(counter))
                    counter = Long.valueOf(0);
                else counter++;
                num ^= toBeDec;
                List<Byte> asciiBytes = longtoBytes(num);
                pw.print(bytesToString(asciiBytes));
                tmp = "";
            }
        }
        pw.close();
    }

    public void receiveCFB(String msg) throws Exception {
        String tmp = "";
        PrintWriter pw = new PrintWriter("receivedMsg.txt");
        Long last = IV;
        Long lastCiph = IV;
        for (int i=0;i<msg.length();i+=2){
                tmp = msg.substring(i,i+2);
                last <<= s * ((i>0)?1:0);
                last |= (i>0?lastCiph:0);
                Long toBeEnc = HexToLong(tmp);
                Long num = des.encrypt(last, key);
                num >>>= (64-8);
                num^= toBeEnc;
                lastCiph = toBeEnc;
                pw.print((char) num.intValue());
        }
        pw.close();
    }

    public void receiveCBC(String msg) throws Exception {
        String tmp = "";
        PrintWriter pw = new PrintWriter("receivedMsg.txt");
        Long last = IV;
        for (int i=0;i<msg.length();++i){
            tmp+= msg.charAt(i);
            if (tmp.length() == 11){
                Long toBeDec = Base64ToLong(tmp);
                Long num = des.decrypt(toBeDec, key);
                num ^= last;
                last = toBeDec;
                List<Byte> asciiBytes = longtoBytes(num);
                pw.print(bytesToString(asciiBytes));
                tmp = "";
            }
        }
        pw.close();
    }


    public void receiveECB(String msg) throws Exception {
        String tmp = "";
        PrintWriter pw = new PrintWriter("receivedMsg.txt");
        for (int i=0;i<msg.length();++i){
           tmp+= msg.charAt(i);
           if (tmp.length() == 11){
                Long num = des.decrypt(Base64ToLong(tmp), key);
                List<Byte> asciiBytes = longtoBytes(num);
                pw.print(bytesToString(asciiBytes));
                tmp = "";
           }
        }
        pw.close();
    }

}