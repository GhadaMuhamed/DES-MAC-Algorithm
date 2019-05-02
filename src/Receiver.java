import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public class Receiver {
    des.DES des = new des.DES();
    int s = 8;
    static final String base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Long key, IV;
    int mode;
    void getKey() throws Exception {
        Scanner sc = new Scanner(new File("DesKey.txt"));
        key = sc.nextLong();
        Scanner sc2 = new Scanner(new File("additionalOutputs.txt"));
        if (sc2.hasNext())
            mode = Integer.valueOf(readFromFile("mode.txt"));

        if (mode == 4)
            IV = Long.valueOf(sc2.nextLine());
        else   IV = receiveECBLong(sc2.nextLine());

    }

    public Receiver() throws Exception {
        getKey();
    }


    private static String readFromFile(String filename) throws Exception {
        Scanner sc = new Scanner(new File(filename));
        return sc.nextLine();
    }


    public void receive() throws Exception {
        String Text = readFromFile("sentMsg.txt");
        String HM = Text.substring(Text.length() - 56);
        String msg = Text.substring(0, Text.length() - 56);
        String plaintext;
        if (mode == 1)
            plaintext = receiveECB(msg);
        else if (mode == 2)
            plaintext = receiveCBC(msg);
        else if (mode == 3)
            plaintext = receiveCFB(msg);
        else if (mode == 4)
            plaintext = receiveOFB(msg);
        else plaintext = receiveCnt(msg);
        System.out.println(plaintext);
        String macKey = getMACKey();
        MAC HMAC = new MAC(macKey);
        String HMnew = HMAC.getHMAC(plaintext);

        if(HMnew.equals(HM)){
            System.out.println(plaintext);
        }
        else{
            System.out.println("The message is invalid!");
        }
    }

    private String getMACKey() {  // check what is the format of the message!

        //Read the sent message!
        Scanner scanner;
        File file = new File("secretKey.txt");
        String key = "";

        try {
            scanner = new Scanner(file);
            key = scanner.nextLine();

            scanner.close();
        } catch (FileNotFoundException er) {
            er.printStackTrace();
        }
        return key;
    }


    Long binaryToLong(String s){
        return new BigInteger(s, 2).longValue();
    }

    public String longToBinary(Long num){
        String res = "";
        res = String.format("%64s", Long.toBinaryString(num)).replace(' ', '0');
        return res;
    }
    public String Base64ToBinary(String s){
        String res = "";
        for (int i = 0; i < s.length(); ++i) {
            Integer decode = base64_chars.indexOf(s.charAt(i));
            res += String.format("%6s", Integer.toBinaryString(decode & 0xFF)).replace(' ', '0');
        }
        return res;
    }
    String binaryToAscii(String s){
        String res = "";
        String tmp = "";
        for (int i=0;i<s.length();++i){
            tmp+=s.charAt(i);
            if (tmp.length()==8){
                int x = Integer.parseInt(tmp,2);
                if (x>0)
                    res+=(char)x;
                tmp="";
            }
        }
        if (tmp.length()>0){
            int x = Integer.parseInt(tmp,2);
            if (x>0)
                res+=(char)x;
        }
        return res;
    }


    public String receiveOFB(String msg) throws Exception {
        char flag = msg.charAt(0);
        int bit = base64_chars.indexOf(msg.charAt(1));
        msg = Base64ToBinary(msg.substring(2));
        if (flag== '1') bit = 0;
        else bit++;
        String res = "";
        String tmp = "";
        Long nonce = IV;
        for (int i = 0; i < msg.length(); ++i) {
            tmp += msg.charAt(i);
            if (tmp.length() == 64) {
                Long toBeDec = binaryToLong(tmp);
                Long num = des.encrypt(nonce, key);
                nonce = num;
                num ^= toBeDec;
                res += longToBinary(num);
                tmp = "";
            }
        }

        if (tmp.length()>0 && bit > 0){
            tmp = tmp.substring(0,bit);
            Long toBeDec = binaryToLong(tmp);
            Long enc = des.encrypt(nonce, key);
            enc >>>= (64 - bit);
            enc ^= toBeDec;
            String str = longToBinary(enc);
            res += str.substring(str.length()-(bit));
        }
        return binaryToAscii(res);
    }

    public String receiveCnt(String msg) throws Exception {
        char flag = msg.charAt(0);
        int bit = base64_chars.indexOf(msg.charAt(1));
        msg = Base64ToBinary(msg.substring(2));
        if (flag== '1') bit = 0;
        else bit++;
        String res = "";
        String tmp = "";
        Long counter = IV;
        System.out.println(counter);
        BigInteger bg = new BigInteger("18446744073709551615");
        for (int i = 0; i < msg.length(); ++i) {
            tmp += msg.charAt(i);
            if (tmp.length() == 64) {
                Long toBeDec = binaryToLong(tmp);
                Long num = des.encrypt(counter, key);
                if (bg.equals(counter))
                    counter = Long.valueOf(0);
                else counter++;
                num ^= toBeDec;
                res += longToBinary(num);
                tmp = "";
            }
        }

        if (tmp.length()>0 && bit > 0){
            tmp = tmp.substring(0,bit);
            Long toBeDec = binaryToLong(tmp);
            Long num = des.encrypt(counter, key);
            num >>>= (64 - bit);
            num ^= toBeDec;
            String str = longToBinary(num);
            res += str.substring(str.length()-bit);
        }
        return binaryToAscii(res);
    }

    public String receiveCFB(String msg) throws Exception {
        String res = "";
        String tmp = "";
        Long last = IV;
        Long lastCiph = IV;
        msg = Base64ToBinary(msg);

        for (int i = 0; i+8 <= msg.length(); i += 8) {
            last <<= s * ((i > 0) ? 1 : 0);
            last |= (i > 0 ? lastCiph : 0);
            tmp = msg.substring(i, i + 8);
            Long toBeEnc = binaryToLong(tmp);
            Long num = des.encrypt(last, key);
            num >>>= (64 - 8);
            num ^= toBeEnc;
            lastCiph = toBeEnc;
            res += (char) num.intValue();
        }
        return res;
    }

    public String receiveCBC(String msg) throws Exception {
        msg = Base64ToBinary(msg);
               String res = "";
        String tmp;
        Long last = IV;
        for (int i = 0; i+64 <= msg.length(); i+=64) {
            tmp = msg.substring(i,i+64);
            Long toBeDec = binaryToLong(tmp);
            Long num = des.decrypt(toBeDec, key);
            num ^= last;
            last = toBeDec;
            res += longToBinary(num);
        }
        return binaryToAscii(res);
    }


    public String receiveECB(String msg) throws Exception {
        msg = Base64ToBinary(msg);
        String res = "";
        String tmp = "";
        for (int i = 0; i+64 <= msg.length(); i+=64) {
            tmp = msg.substring(i,i+64);
            Long num = des.decrypt(binaryToLong(tmp), key);
            res += longToBinary(num);

        }
        return binaryToAscii(res);
    }


    public Long receiveECBLong(String msg) throws Exception {
        msg = Base64ToBinary(msg);
        String res = "";
        String tmp = "";
        Long num=Long.valueOf(0);
        for (int i = 0; i+64 <= msg.length(); i+=64) {
            tmp = msg.substring(i,i+64);
             num = des.decrypt(binaryToLong(tmp), key);
        }
        return num;
    }
    public static void main(String[] args) throws Exception {
        Receiver r = new Receiver();
        r.receive();

    }
}
