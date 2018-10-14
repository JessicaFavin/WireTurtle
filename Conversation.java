import java.nio.file.*;
import java.util.*;
import java.io.*;

public class Conversation {
  private ArrayList<Layer4> packetList;

  public Conversation() {
    this.packetList = new ArrayList<Layer4>();
  }

  public void addMessage(Layer4 packet) {
    this.packetList.add(packet);
  }
}
