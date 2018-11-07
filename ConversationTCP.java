import java.nio.file.*;
import java.util.*;
import java.io.*;

public class ConversationTCP {
  private String id;
  private String data;
  private String protocol;
  private ArrayList<Ethernet> packetList;


  public ConversationTCP(String id) {
    this.id = id;
    this.data = "";
    this.protocol = "unknown";
    this.packetList = new ArrayList<Ethernet>();
  }

  public void addPaquet(Ethernet ef) {
    if(!this.packetList.contains(ef)){
      this.packetList.add(ef);
    } else {
      int packetIndex = this.packetList.indexOf(ef);
      //removes old one
      this.packetList.remove(packetIndex);
      //add the most updated one
      this.packetList.add(packetIndex, ef);

    }
  }

  public void recompose() {
    String res = "";
    int i = 1;
    String currentId = "";
    String data;;
    for(Ethernet ef : packetList) {
      data = ef.getTcpData();
      if(!data.trim().equals("")){
        currentId = (ef.getIpSrc()+ef.getPortSrc()+ef.getIpDst()+ef.getPortDst());
        if(this.id.equals(currentId)){
            res += "> \u001B[34m";
        } else {
          res += "< \u001B[31m";
        }
        res += Tools.hexToAscii(data)+"\u001B[0m\n";
      }
    }
    this.data = res;
    this.guessProtocol();
  }

  private void guessProtocol() {
    if(this.data.contains("HTTP")){
      this.protocol = "HTTP";
      for(Ethernet ef: packetList){
        if(!ef.isDHCP() && !ef.isDNS() && !ef.isFTP()) {
          ef.constructHTTP();
        }
      }
    }
    if(this.data.contains("227 Entering Passive Mode")) {
      //only recognizes passive FTP
      this.protocol = "FTP";
      for(Ethernet ef: packetList){
        if(!ef.isDHCP() && !ef.isDNS() && !ef.isHTTP()) {
          ef.constructFTP();
        }
      }
    }
  }

  public boolean contains(Ethernet ef) {
    return this.packetList.contains(ef);
  }

  @Override
  public String toString() {
    return this.data+"\n";
  }

}
