import java.nio.file.*;
import java.util.*;
import java.io.*;

public abstract class Packet {
  private HashMap<String, byte[]>  header;
  private int[] fields_size;
  //private byte[] data;
  private Packet encapsulated_packet;
  public abstract HashMap<String, byte[]>  getHeader();
}
