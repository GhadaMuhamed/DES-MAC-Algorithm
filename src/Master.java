import java.time.LocalTime;
import static java.time.temporal.ChronoUnit.MILLIS;

public class Master {

    public static void main(String[] args) throws Exception {

        Long totalTime = Long.valueOf(0);
        Sender sender = new Sender();
        for (int i=0;i<10;++i) {
            LocalTime t1 = java.time.LocalTime.now();
            sender.send();
            LocalTime t2 = java.time.LocalTime.now();
            totalTime +=MILLIS.between(t1, t2);
        }
        System.out.println(totalTime/10);
    }
}
