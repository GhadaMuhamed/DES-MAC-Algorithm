import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

import static java.lang.StrictMath.max;

public class Sender {


    des.DES des = new des.DES();
    static final String base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    Long key,IV;
    int s = 8;
    int mode= 3;
    void getKey() throws Exception {
        Random r = new Random();
        key = r.nextLong();
        PrintWriter pw = new PrintWriter(new File("DesKey.txt"));
        IV = r.nextLong();
        pw.println(key);
        pw.close();
        pw = new PrintWriter(new File("mode.txt"));
        pw.println(mode);
        pw.close();
        if (mode!= 4){
            pw = new PrintWriter(new File("additionalOutputs.txt"));
            pw.print(sendECBLong(IV));
            pw.close();
        }

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

    public void send() throws Exception {
        PrintWriter cipher = new PrintWriter("sentMsg.txt");
        Scanner sc = new Scanner(new File("MessageToBeSent.txt"));
        String msg = sc.nextLine();

        byte[] plainBytes = msg.getBytes();
        String plainBinary;

        plainBinary = bytesToBinary(plainBytes);

        String cipherTxt = new String();
        if (mode == 1)
            cipherTxt = sendECB(plainBinary);
        else if (mode == 2)
            cipherTxt = sendCBC(plainBinary);
        else if (mode == 3)
            cipherTxt = sendCFB(plainBytes);
        else if (mode == 4)
            cipherTxt = sendOFB(plainBinary);
        else cipherTxt = sendCnt(plainBinary);

        SecretKey macSk = new SecretKey();
        macSk.run();
        String macKey = getMACKey();
        MAC HMAC = new MAC(macKey);
        String M = HMAC.getHMAC(msg);
        cipher.print(cipherTxt+M);
        cipher.close();
    }

    String bytesToBinary(byte[] arr){
        String s = "";
        for (int i=0;i<arr.length;++i){
            s += String.format("%8s", Integer.toBinaryString(arr[i] & 0xFF)).replace(' ', '0');
        }
        return s;
    }


    Long binaryToLong(String s){
        return new BigInteger(s, 2).longValue();
    }

    String longToBinary(Long num){
            return String.format("%64s", Long.toBinaryString(num)).replace(' ', '0');
    }

    String numToBinary(Long num,Integer len){
        return String.format("%"+ len.toString() + "s", Long.toBinaryString(num)).replace(' ', '0');

    }
    String binaryToBase64(String s){
        String tmp ="";
        String res = "";
        String z = "";
        for (int i=0;i<s.length();++i){
            tmp+=s.charAt(i);
            if (tmp.length()==6){
                Integer b  = Integer.parseInt(tmp, 2);
                res += base64_chars.charAt(b);
                tmp="";
            }
        }
        if (tmp.length()>0){
            while (tmp.length()<6)
                tmp +='0';
            Integer b  = Integer.parseInt(tmp, 2);
            res += base64_chars.charAt(b);
        }

        return res;
    }

    public String sendOFB(String msg)throws Exception{
        String res = "";
        Random r = new Random();
        Long nonce = r.nextLong();
        PrintWriter pw = new PrintWriter(new File("additionalOutputs.txt"));
        pw.print(nonce);
        pw.close();
        String tmp = "";
        for (int i = 0; i < msg.length(); i++) {
            tmp += msg.charAt(i);
            if (tmp.length() == 64){
                Long plainLong = binaryToLong(tmp);
                Long enc = des.encrypt(nonce, key);
                nonce = enc;
                enc ^= plainLong;
                res += longToBinary(enc);
                tmp = "";
            }
        }
        int bit = 0;
        if (tmp.length() > 0) {
            bit = tmp.length()-1;
            Long plainLong = binaryToLong(tmp);
            Long enc = des.encrypt(nonce, key);
            enc >>>= (64 - bit - 1);
            enc ^= plainLong;
            res += numToBinary(enc, bit+1);
        }
        Integer flag = 0;
        if (tmp.length()==0)
            flag = 1;
        return flag.toString() + base64_chars.charAt(bit) + binaryToBase64(res);
    }


    public String sendCnt(String msg)throws Exception{
        String res = "";
        String tmp = "";
        BigInteger bg = new BigInteger("18446744073709551615");
        Long counter = IV;

        for (int i = 0; i < msg.length(); ++i) {
            tmp += msg.charAt(i);
            if (tmp.length() == 64) {
                Long plainLong = binaryToLong(tmp);
                Long enc = des.encrypt(counter, key);
                if (bg.equals(counter))
                    counter = Long.valueOf(0);
                else counter++;
                enc ^= plainLong;
                res += longToBinary(enc);
                tmp = "";
            }
        }
        int bit = max(tmp.length()-1,0);
        if (tmp.length() > 0) {
            Long plainLong = binaryToLong(tmp);
            Long enc = des.encrypt(counter, key);
            counter++;
            enc >>>= (64 - bit - 1);
            enc ^= plainLong;
            res += numToBinary(enc,bit+1);
        }
        Integer flag = 0;
        if (tmp.length()==0)
            flag = 1;
        return flag.toString() + base64_chars.charAt(bit) + binaryToBase64(res);

    }


    public String sendCFB(byte[] msg)throws Exception {
        String res = "";
        Long last = IV;
        Long lastCiph = last;
        for (int i = 0; i < msg.length; i++) {
            byte cur = msg[i];
            last <<= s * ((i>0)?1:0);
            last |= (i>0?lastCiph:0);
            Long enc = des.encrypt(last, key);
            enc >>>= (64-8);
            enc ^= cur;
            lastCiph = enc;
            res += numToBinary(enc,8);
        }
        return binaryToBase64(res);
    }


    public String sendCBC(String msg)throws Exception {
        String res = "";
        Long last = IV;
        String tmp = "";
        for (int i = 0; i < msg.length(); ++i) {
            tmp += msg.charAt(i);
            if (tmp.length() == 64) {
                Long toBeEnc = binaryToLong(tmp);
                toBeEnc ^= last;
                Long enc = des.encrypt(toBeEnc, key);
                last = enc;
                res += longToBinary(enc);
                tmp = "";
            }
        }
        if (tmp.length() > 0) {
            Long toBeEnc = binaryToLong(tmp);
            toBeEnc ^= last;
            Long enc = des.encrypt(toBeEnc, key);
            res += longToBinary(enc);
        }

        return binaryToBase64(res);
    }
    public String sendECB(String msg) throws Exception {
        String res = "";
        String tmp = "";
        for (int i = 0; i < msg.length(); ++i) {
            tmp += msg.charAt(i);
            if (tmp.length() == 64) {
                Long num = binaryToLong(tmp);
                Long enc = des.encrypt(num, key);
                res += longToBinary(enc);
                tmp = "";
            }
        }
        if (tmp.length() > 0) {
            Long enc = des.encrypt(binaryToLong(tmp), key);
            res += longToBinary(enc);
        }
        return binaryToBase64(res);
    }


    public String sendECBLong(Long num) throws Exception {
                Long enc = des.encrypt(num, key);
        return binaryToBase64(longToBinary(enc));
    }

    public static void main(String[] args)throws Exception{
        Sender sender = new Sender();
        sender.send();

    }
}