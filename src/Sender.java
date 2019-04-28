import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Scanner;

public class Sender {


    DES des = new DES();
    static final String base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Long key, IV;
    int s = 8;
    void getKey() throws Exception {
        Scanner sc = new Scanner(new File("DesKey.txt"));
        key = sc.nextLong();
        IV = sc.nextLong();
    }
    public Sender() throws Exception {
     getKey();
    }

    private String getMACKey(){  // check what is the format of the message!

        //Read the sent message!
        Scanner scanner;
        File file = new File("secretKey.txt");
        String key="";

        try{
            scanner=new Scanner(file);
            key = scanner.nextLine();

            scanner.close();
        }
        catch (FileNotFoundException er) {
            er.printStackTrace();
        }
        return key;
    }

    public void send(int mode) throws Exception {
        PrintWriter cipher = new PrintWriter("sentMsg.txt");
        Scanner sc = new Scanner(new File("MessageToBeSent.txt"));
        String msg = sc.nextLine();
        PrintWriter pw = new PrintWriter("mode.txt");
        pw.println(mode);
        pw.close();
        String cipherTxt = new String();
        if (mode == 1)
            cipherTxt = sendECB(msg);
        else if (mode == 2)
            cipherTxt = sendCBC(msg);
        else if (mode == 3)
            cipherTxt = sendCFB(msg);
        else if (mode == 4)
            cipherTxt = sendOFB(msg);
        else cipherTxt = sendCnt(msg);

        SecretKey macSk = new SecretKey();
        macSk.run();
        String macKey = getMACKey();
        MAC HMAC = new MAC(macKey);
        String M = HMAC.getHMAC(msg);
        cipher.print(cipherTxt+M);
        cipher.close();
    }

    Long bytesToLong(byte[] ls){
        String s = "";
        for (int i=0;i<9;++i)
            s += String.format("%7s", Integer.toBinaryString(ls[i] & 0xFF)).replace(' ', '0');
            //System.out.println(s);
        Long num = Long.parseLong(s,2);
        return num;
    }

    String Base64Enc(Long num){
        String s = Long.toBinaryString(num);
        String z = "";
        while (s.length()+z.length()<66)
            z +='0';
        String bin = z+s;
        String tmp = "";
        String res = "";
        for (int i=0;i<bin.length();++i){
            tmp += bin.charAt(i);
            if (tmp.length() == 6){
                Integer b  = Integer.parseInt(tmp, 2);
                res += base64_chars.charAt(b);
                tmp = "";
            }
        }
        return res;
    }

    String ToHex(Long num){
        String s = String.format("%2X", num).replace(' ', '0');;
        return s;

    }
    public String sendOFB(String msg)throws Exception{
        byte[] plainText = msg.getBytes();
        byte[] ls = new byte[9];
        String res = "";
        int cnt = 0;
        Long nonce = IV;
        for (int i = 0; i < plainText.length; ++i) {
            ls[cnt++] = plainText[i];
            if (cnt == 9) {
                Long plainLong = bytesToLong(ls);
                Long enc = des.encrypt(nonce, key);
                nonce = enc;
                enc ^= plainLong;
                res += Base64Enc(enc);
                cnt = 0;
            }
        }

        if (cnt > 0) {
            for (int i = cnt; i < 9; ++i)
                ls[i] = 0;
            Long plainLong = bytesToLong(ls);
            Long enc = des.encrypt(nonce, key);
            enc ^= plainLong;
            res += Base64Enc(enc);
        }
        return res;
    }


    public String sendCnt(String msg)throws Exception {
        byte[] plainText = msg.getBytes();
        byte[] ls = new byte[9];
        int cnt = 0;
        String res = "";
        BigInteger bg = new BigInteger("18446744073709551615");
        Long counter = IV;
        for (int i = 0; i < plainText.length; ++i) {
            ls[cnt++] = plainText[i];
            if (cnt == 9) {
                Long plainLong = bytesToLong(ls);
                //toBeEnc ^= last;
                Long enc = des.encrypt(counter, key);
                if (bg.equals(counter))
                    counter = Long.valueOf(0);
                else counter++;
                enc ^= plainLong;
                res += Base64Enc(enc);
                cnt = 0;
            }
        }
        if (cnt > 0) {
            for (int i = cnt; i < 9; ++i)
                ls[i] = 0;
            Long plainLong = bytesToLong(ls);
            //toBeEnc ^= last;
            Long enc = des.encrypt(counter, key);
            counter++;
            enc ^= plainLong;
            res += Base64Enc(enc);
        }
        return res;
    }


    public String sendCFB(String msg)throws Exception {
        String res = "";
        byte[] plainText = msg.getBytes();
        int cnt = 0;
        Long last = IV;
        Long lastCiph = IV;
        for (int i = 0; i < plainText.length; ++i) {
            byte cur = plainText[i];
            last <<= s * ((i>0)?1:0);
            last |= (i>0?lastCiph:0);
            Long enc = des.encrypt(last, key);
            enc >>>= (64-8);
            enc ^= cur;
            lastCiph = enc;
            res += ToHex(enc);
        }
        return res;
    }


    public String sendCBC(String msg)throws Exception {
        String res = "";
        byte[] plainText = msg.getBytes();
        byte[] ls = new byte[9];
        int cnt = 0;
        Long last = IV;
        for (int i = 0; i < plainText.length; ++i) {
            ls[cnt++] = plainText[i];
            if (cnt == 9) {
                Long toBeEnc = bytesToLong(ls);
                toBeEnc ^= last;
                Long enc = des.encrypt(toBeEnc, key);
                last = enc;
                res+=Base64Enc(enc);
                cnt = 0;
            }
        }
        if (cnt > 0) {
            for (int i = cnt; i < 9; ++i)
                ls[i] = 0;
            Long toBeEnc = bytesToLong(ls);
            toBeEnc ^= last;
            Long enc = des.encrypt(toBeEnc, key);
            res+=Base64Enc(enc);
        }
        return res;
    }
    public String sendECB(String msg) throws Exception {
        byte[] plainText = msg.getBytes();
        String res = "";
        byte[] ls = new byte[9];
        int cnt = 0;
        for (int i = 0; i < plainText.length; ++i) {
            ls[cnt++] = plainText[i];
            if (cnt == 9) {
                Long num = bytesToLong(ls);
                Long enc = des.encrypt(bytesToLong(ls), key);
                res += Base64Enc(enc);
                cnt = 0;
            }
        }
        if (cnt > 0) {
            for (int i = cnt; i < 9; ++i)
               ls[i] = 0;
            Long enc = des.encrypt(bytesToLong(ls), key);
            res += Base64Enc(enc);
        }
       return res;
    }


}
