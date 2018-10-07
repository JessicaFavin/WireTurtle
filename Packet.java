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
  abstract void setPacket(byte[] packet);
}
