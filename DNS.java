import java.nio.file.*;
import java.util.*;
import java.io.*;

public class DNS extends Packet {

  private static final String[] fields_name = {"id", "flags", "questions", "answer RRs",
  "authority RRs", "addiditonal RRs", "data"};
  private int[] fields_size = {2, 2, 2, 2, 2, 2, 0};
  private static int header_total = 12;
  private HashMap<String, String> header;
  private Packet encapsulated_packet;
  private byte[] raw_data;
  private HashMap<String, Integer> flags;
  private final String[] flags_name = {"response", "opcode", "authoritative",
  "truncated", "recursion desired", "recursion available", "Z", "answer authenticated",
  "non-authenticated data", "reply code"};
  private final int[] flags_mask = {0x8000, 0x7800, 0x0400, 0x0200, 0x0100,
    0x0080, 0x0040, 0x0020, 0X0010, 0x000f};
  private final int[] flags_shift = {15, 11, 10, 9, 8, 7, 6, 5, 4, 0};
  private int queries_nb;
  private int answers_nb;

  public DNS(byte[] packet) {
    this.raw_data = null;
    this.encapsulated_packet = null;
    this.header = new HashMap<String, String>();
    this.flags = new HashMap<String, Integer>();
    this.setPacket(packet);
    this.setFlags();
    this.setData();
  }

  @Override
  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      if(size==0) {
        //à adapter
        size = (packet.length-header_total);
        fields_size[i] = size;
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet, offset, offset+size);
        this.raw_data = buffer;
      } else {
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet, offset, offset+size);
      }
      header.put(fields_name[i], Tools.hexToString(buffer));
      offset += size;
    }
  }

  public void setData() {
    queries_nb =  Integer.parseInt(header.get("questions"),16);
    answers_nb =  Integer.parseInt(header.get("answer RRs"),16);
    //queries
    for(int i=0; i<queries_nb; i++) {
      //read bytes until 00 -> name + name length for answers maybe

      // read 2 bytes for type then 2 bytes for class
    }
    //answers
    for(int i=0; i<answers_nb; i++) {
      //read bytes until 00 -> name or name length if set

      // read 2 bytes for type then 2 bytes for class, 4 byts for ttl
      // 2 bytes for data length + data length bytes for address
      // 16 bytes for IPv6 4 bytes for IPv4
    }
  }

  private void setFlags() {
    int flags_hex = Integer.parseInt(header.get("flags"), 16);
    for(int i=0; i<flags_name.length; i++) {
      int value = (flags_hex & flags_mask[i])>> flags_shift[i];
      flags.put(flags_name[i], value);
    }
  }
  /**
  *  Reply code values
  *  0 – Pas d’erreur / No error
  *  1 – Erreur de format dans la requête
  *  2 – Problème sur serveur
  *  3 – Le nom n’existe pas / No such name
  *  4 – Non implémenté
  *  5 – Refus
  *  6-15 – Réservés
  *
  **/
  @Override
  public String toString() {
    String res = "Domain Name System\n";
    res += "Reply code: \t"+Tools.dnsReplyCode(flags.get("reply code"))+"\n";
    res += "Looking for :\t"+Tools.dnsResolution(header.get("data"))+"\n";
    return res;
  }

}
