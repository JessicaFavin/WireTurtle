import java.nio.file.*;
import java.util.*;
import java.io.*;

public class ConversationTCP {
  private HashMap<String, String> dataList;
  private String data;

  public ConversationTCP() {
    this.dataList = new HashMap<String,String>();
    this.data = "";
  }

  public void addData(String seqNumber, String data) {
    this.dataList.put(seqNumber, data);
  }

  public void recompose() {
    String res = "";
    System.out.println("Length : "+dataList.size());
    int i = 1;
    for(Map.Entry entry : dataList.entrySet()) {
      System.out.println("i : "+(i++)+" res : "+Tools.hexToAscii(entry.getValue().toString()));
      res += Tools.hexToAscii(entry.getValue().toString());
    }
    this.data = res;
  }

  @Override
  public String toString() {
    return this.data+"\n";
  }

}
