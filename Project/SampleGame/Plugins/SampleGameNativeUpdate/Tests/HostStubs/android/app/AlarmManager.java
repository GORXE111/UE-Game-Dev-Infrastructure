package android.app;
public class AlarmManager {
    public static final int ELAPSED_REALTIME=3;
    public PendingIntent lastScheduled,lastCancelled;public int scheduleCount,type;public long at;
    public void setExact(int type,long at,PendingIntent pending){this.type=type;this.at=at;lastScheduled=pending;scheduleCount++;}
    public void cancel(PendingIntent pending){lastCancelled=pending;}
}
