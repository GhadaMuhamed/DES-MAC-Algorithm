import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.time.LocalTime;
import java.util.Random;
import java.util.Scanner;

import static java.time.temporal.ChronoUnit.MILLIS;

public class Master {


    public static void main(String[] args) throws Exception {
       // DES des = new DES();
        //des.generateKey();
        Random r = new Random();
        Long key = r.nextLong();
        Long IV = r.nextLong();
        //Long IV = Long.valueOf(124586);
        //Long key = Long.valueOf("8361560199268602064");
        //Receiver receiver = new Receiver();
        //Long ss =  receiver.Base64ToLong("NGsgjU27aAV");
        PrintWriter pw = new PrintWriter("DesKey.txt");
        pw.println(key);
        pw.println(IV);
        pw.close();
        Sender sender = new Sender();
        LocalTime t1 = java.time.LocalTime.now();
        sender.send(3);
        LocalTime t2 = java.time.LocalTime.now();
        System.out.println("Time for sending: ");
        System.out.println(MILLIS.between(t1,t2));
        System.out.println("Time for Receiving: ");
        //LocalTime t3 = java.time.LocalTime.now();
        //Receiver receiver = new Receiver();
        //receiver.receive();
        //LocalTime t4 = java.time.LocalTime.now();
        //System.out.println(MILLIS.between(t3,t4));

    }
}
