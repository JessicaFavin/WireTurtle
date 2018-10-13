import java.nio.file.*;
import java.util.*;
import java.io.*;

public class Layer7 extends Packet {
  private byte[] raw_data;

  @Override
  public void setPacket(byte[] packet) {
    this.raw_data = packet;
  }
}
