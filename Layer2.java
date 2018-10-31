import java.nio.file.*;
import java.util.*;
import java.io.*;

public class Layer2 extends Packet {
  private byte[] raw_data;

  @Override
  public void setPacket(byte[] packet) {
    this.raw_data = packet;
  }

  @Override
  public boolean isARP(){
    return false;
  }
  @Override
  public boolean isICMP(){
    return false;
  }
  @Override
  public boolean isIP(){
    return false;
  }
  @Override
  public boolean isUDP(){
    return false;
  }
  @Override
  public boolean isTCP(){
    return false;
  }
  @Override
  public boolean isDNS(){
    return false;
  }
  @Override
  public boolean isDHCP(){
    return false;
  }
  @Override
  public boolean isHTTP(){
    return false;
  }
  @Override
  public boolean isFTP(){
    return false;
  }

  @Override
  public boolean hasSyn(){
    if(this.isTCP()) {
      return this.encapsulated_packet.hasSyn();
    }
    return false;
  }

  @Override
  public boolean hasAck(){
    if(this.isTCP()) {
      return this.encapsulated_packet.hasAck();
    }
    return false;
  }

}
