import java.nio.file.*;
import java.util.*;
import java.io.*;

public abstract class Packet {
  private HashMap<String, String>  header;
  private static int header_total;
  private static String[] fields_name;
  private int[] fields_size;
  private Packet encapsulated_packet;
  private byte[] raw_data;
  public abstract void setPacket(byte[] packet);
  public abstract boolean isARP();
  public abstract boolean isICMP();
  public abstract boolean isIP();
  public abstract boolean isUDP();
  public abstract boolean isTCP();
  public abstract boolean isDNS();
  public abstract boolean isDHCP();
  public abstract boolean isHTTP();
  public abstract boolean isFTP();
}
