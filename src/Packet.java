

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;

public class Packet {
	ArrayList<String> content=new ArrayList<String>();
	String summary;

	//Ethernet
	String fMac,tMac;
	String type;
	
	String exp;
	Date d;
	static String[] win=new String[7]; 
	void analyze() throws UnknownHostException {
		d=new Date();
		int ind=0;
//		String s=(String)content.stream().reduce((String)(s1,s2)->s1+s2);
		String s="";
		for(int i=0;i<content.size();i++) {
			s+=content.get(i);
		}
		fMac=hexr(s.substring(ind,ind+=12));
		tMac=hexr(s.substring(ind,ind+=12));
		System.out.println("types:"+s.substring(ind,ind+4));
		byte[] type=Create.hex2bin(s.substring(ind,ind+=4));
		System.out.println("type:"+type[0]+" "+type[1]+" "+type.length);
		System.out.println("8="+(new byte[]{(byte) 0x08,0x00})[1]);
		this.type=slot(type);
		System.out.println("type:"+this.type);
		exp+="\nEthernet Frame info\n"
				+ "Destination:"+fMac+"\nSource:"+tMac+"\ntype:"+this.type;
		switch(this.type) {
		case "ARP":
			Arp arp=new Arp();
			arp.len=String.valueOf(s.length()/2);
			byte[] htype=Create.hex2bin(s.substring(ind,ind+=4));
			if(beq(htype,"0001"))arp.htype="Ethernet";
			else arp.htype=Create.bin2hex(htype);
			System.out.println("htype:"+Create.bin2hex(htype));
			byte[] ptype=Create.hex2bin(s.substring(ind,ind+=4));
			arp.ptype=slot(ptype);
			System.out.println("protocol:"+arp.ptype);
			String hsize=s.substring(ind,ind+=2);
			String psize=s.substring(ind,ind+=2);
			byte[] opcode=Create.hex2bin(s.substring(ind,ind+=4));
			arp.hsize=hsize;
			arp.psize=psize;
			if(beq(opcode,"0001"))arp.opcode="request";
			else if(beq(opcode,"0002"))arp.opcode="reply";
			else if(beq(opcode,"0003"))arp.opcode="rrp request";
			else if(beq(opcode,"0004"))arp.opcode="rarp reply";
			System.out.println("opcode:"+arp.opcode);
			String smac=s.substring(ind,ind+=12);
			String sip=s.substring(ind,ind+=8);
			String dmac=s.substring(ind,ind+=12);
			String dip=s.substring(ind,ind+=8);
			InetAddress sipp=InetAddress.getByAddress(Create.hex2bin(sip));
			InetAddress dipp=InetAddress.getByAddress(Create.hex2bin(dip));
			arp.smac=hexr(smac);
			arp.dmac=hexr(dmac);
			arp.sip=sipp.getHostName();
			arp.dip=dipp.getHostName();
			System.out.println("adres"+sipp.getHostName());
			System.out.println("smac:"+arp.smac);
			System.out.println("dmac:"+arp.dmac);
			System.out.println("sip:c4:"+arp.sip);
			System.out.println("dip:"+arp.dip);
			exp+=arp.makeString();
			System.out.println(exp);
			
			win[1]=d.toString();
			win[2]=arp.smac;
			win[3]=arp.dmac;
			win[4]="ARP";
			win[5]=arp.len;
			win[6]="type:"+arp.opcode;
			
			break;
		case "IPv4":
			IPv4 ip=new IPv4();
			String vl=Integer.toBinaryString(Integer.parseInt(s.substring(ind,ind+=2),16));
//			System.out.println("ver:"+vl.substring(0,3));
//			System.out.println("ver:"+vl.substring(3,7));
			ip.version=Integer.toString(Integer.parseInt(vl.substring(0,3),2),10);
			ip.hlen=Integer.toString(Integer.parseInt(vl.substring(3,7),2),10);
//			System.out.println("ttttes");
			ip.dsf=s.substring(ind,ind+=2);
//			System.out.println("ttttes2");
//			ip.tlen=(int)Create.hex2bin(s.substring(ind,ind+=2))[1];
			ip.tlen=Create.hex2int(s.substring(ind,ind+=4));
//			System.out.println("ttttes3");
			ip.iden=s.substring(ind,ind+=4);
//			System.out.println("ttttes3");
			ip.flags=s.substring(ind,ind+=4);
//			System.out.println("ttttes3");
			ip.ttl=Create.hex2int(s.substring(ind,ind+=2));
//			System.out.println("ttttes3");
			String protocol=s.substring(ind,ind+=2);
			System.out.println("prottttttttttttttttttttttttttt"+protocol+" "+roulette(Integer.parseInt(protocol,16)));
			ip.protocol=roulette(Integer.parseInt(protocol,16));
			ip.hc=s.substring(ind,ind+=4);
			ip.source=InetAddress.getByAddress(Create.hex2bin(s.substring(ind,ind+=8))).getHostAddress();
			ip.dest=InetAddress.getByAddress(Create.hex2bin(s.substring(ind,ind+=8))).getHostAddress();
			exp+=ip.makeString();
			
			switch(ip.protocol) {
			case "UDP":
				UDP udp=new UDP(String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),s.substring(ind,ind+=4));
				exp+=udp.makeString();
				summary="port "+udp.fport+" -> "+udp.tport;
				break;
//			default:System.exit(-1);
			}
			System.out.println(exp);
			win[1]=d.toString();
			win[2]=ip.source;
			win[3]=ip.dest;
			win[4]=ip.protocol;
			win[5]=String.valueOf(ip.tlen);
			win[6]=summary;
			break;
		case "IPv6":
			IPv6 ip6=new IPv6();
			String vr=Integer.toBinaryString(Integer.parseInt(s.substring(ind,ind+=2),16));
//			System.out.println("ver:"+vl.substring(0,3));
//			System.out.println("ver:"+vl.substring(3,7));
			ip6.version=Integer.toString(Integer.parseInt(vr.substring(0,3),2),10);
			ip6.plen=Integer.toString(Integer.parseInt(s.substring(ind,ind+=4),16));
			ip6.nh=roulette(Integer.parseInt(s.substring(ind,ind+=2),10));
			ip6.hl=Integer.toString(Integer.parseInt(s.substring(ind,ind+=2),16));
			ip6.source=InetAddress.getByName(iper(s.substring(ind,ind+=32))).getHostAddress();
			ip6.dest=InetAddress.getByName(iper(s.substring(ind,ind+=32))).getHostName();
			ip6.show();
			System.exit(-1);
		default :
			win[1]=d.toString();
			win[2]=fMac;
			win[3]=tMac;
			win[4]=this.type;
			win[5]="60";
			win[6]=summary;
		}
	}
	boolean beq(byte[] a,byte[] b) {
		if(a.length!=b.length)return false;
		for(int i=0;i<a.length;i++) {
//			System.out.println("a:"+a[i]+" b:"+b[i]);
			if(!new Byte(a[i]).equals(new Byte(b[i])))return false;
		}
		return true;
	}
	boolean beq(byte[] a,String s) {
		byte[] b=Create.hex2bin(s);
		return beq(a,b);
	}
	String slot(byte[] type) {
		if(beq(type,"0800"))return "IPv4";
		else if(beq(type,"0800"))return "IPv4";
		else if(beq(type,"0806"))return "ARP";
		else if(beq(type,"8035"))return "RARP";
		else if(beq(type,"805b"))return "VMTP";
		else if(beq(type,"809b"))return "AT";
		else if(beq(type,"80F3"))return "AARP";
		else if(beq(type,"8137"))return "IPX";
		else if(beq(type,"814c"))return "SNMP";
		else if(beq(type,"8191"))return "NB";
		else if(beq(type,"817d"))return "XTP";
		else if(beq(type,"86dd"))return "IPv6";
		else if(beq(type,"8863"))return "PPoE";
		else if(beq(type,"8864"))return "PPoE";
		else if(beq(type,"888e"))return "EAP";
//		else if(beq(type,"8899"))return "LoopSearch";
		else if(beq(type,"9000"))return "LoopBack";
		else {
			String s="";
//			for(int i=0;i<type.length;i++) {
				s+=String.valueOf(Create.bin2hex(type));
//			}
			return s;
		}
	}
	String roulette(int v) {
		switch(v) {
		case 0: return "IP";
		case 1: return "ICMP";
		case 3: return "GGP";
		case 6: return "TCP";
		case 8: return "EGP";
		case 12 :return "PUP";
		case 17 :return "UDP";
		case 20 :return "HMP";
		case 22 :return "XNS-IDP";
		case 77 :return "RDP";
		case 66 :return "RVD";
		default: return String.valueOf(v);
		}
	}
	String hexr(String s) {
		String a="";
		for(int i=0;i<s.length();i+=2) {
			a+=s.substring(i,i+2)+":";
		}
		return a.substring(0,a.length()-1);
	}
	String iper(String s) {
		String a="";
		for(int i=0;i<s.length();i+=4) {
			a+=s.substring(i,i+2)+":";
		}
		return a.substring(0,a.length()-1);
	}
}
/*
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;*/
/*
public class Packet {
	ArrayList<String> content=new ArrayList<String>();
	String summary;

	//Ethernet
	String fMac,tMac;
	String type;
	
	String exp;
	Date d;
	static String[] win=new String[7]; 
	void analyze() throws UnknownHostException {
		d=new Date();
		int ind=0;
//		String s=(String)content.stream().reduce((String)(s1,s2)->s1+s2);
		String s="";
		for(int i=0;i<content.size();i++) {
			s+=content.get(i);
		}
		fMac=hexr(s.substring(ind,ind+=12));
		tMac=hexr(s.substring(ind,ind+=12));
		System.out.println("types:"+s.substring(ind,ind+4));
		byte[] type=Create.hex2bin(s.substring(ind,ind+=4));
		System.out.println("type:"+type[0]+" "+type[1]+" "+type.length);
		System.out.println("8="+(new byte[]{(byte) 0x08,0x00})[1]);
		this.type=slot(type);
		System.out.println("type:"+this.type);
		exp+="\nEthernet Frame info\n"
				+ "Destination:"+fMac+"\nSource:"+tMac+"\ntype:"+this.type;
		switch(this.type) {
		case "ARP":
			Arp arp=new Arp();
			arp.len=String.valueOf(s.length()/2);
			byte[] htype=Create.hex2bin(s.substring(ind,ind+=4));
			if(beq(htype,"0001"))arp.htype="Ethernet";
			else arp.htype=Create.bin2hex(htype);
			System.out.println("htype:"+Create.bin2hex(htype));
			byte[] ptype=Create.hex2bin(s.substring(ind,ind+=4));
			arp.ptype=slot(ptype);
			System.out.println("protocol:"+arp.ptype);
			String hsize=s.substring(ind,ind+=2);
			String psize=s.substring(ind,ind+=2);
			byte[] opcode=Create.hex2bin(s.substring(ind,ind+=4));
			arp.hsize=hsize;
			arp.psize=psize;
			if(beq(opcode,"0001"))arp.opcode="request";
			else if(beq(opcode,"0002"))arp.opcode="reply";
			else if(beq(opcode,"0003"))arp.opcode="rrp request";
			else if(beq(opcode,"0004"))arp.opcode="rarp reply";
			System.out.println("opcode:"+arp.opcode);
			String smac=s.substring(ind,ind+=12);
			String sip=s.substring(ind,ind+=8);
			String dmac=s.substring(ind,ind+=12);
			String dip=s.substring(ind,ind+=8);
			InetAddress sipp=InetAddress.getByAddress(Create.hex2bin(sip));
			InetAddress dipp=InetAddress.getByAddress(Create.hex2bin(dip));
			arp.smac=hexr(smac);
			arp.dmac=hexr(dmac);
			arp.sip=sipp.getHostName();
			arp.dip=dipp.getHostName();
			System.out.println("adres"+sipp.getHostName());
			System.out.println("smac:"+arp.smac);
			System.out.println("dmac:"+arp.dmac);
			System.out.println("sip:c4:"+arp.sip);
			System.out.println("dip:"+arp.dip);
			exp+=arp.makeString();
			System.out.println(exp);
			
			win[1]=d.toString();
			win[2]=arp.smac;
			win[3]=arp.dmac;
			win[4]="ARP";
			win[5]=arp.len;
			win[6]="type:"+arp.opcode;
			
			break;
		case "IPv4":
			IPv4 ip=new IPv4();
			String vl=Integer.toBinaryString(Integer.parseInt(s.substring(ind,ind+=2),16));
//			System.out.println("ver:"+vl.substring(0,3));
//			System.out.println("ver:"+vl.substring(3,7));
			ip.version=Integer.toString(Integer.parseInt(vl.substring(0,3),2),10);
			ip.hlen=Integer.toString(Integer.parseInt(vl.substring(3,7),2),10);
//			System.out.println("ttttes");
			ip.dsf=s.substring(ind,ind+=2);
//			System.out.println("ttttes2");
//			ip.tlen=(int)Create.hex2bin(s.substring(ind,ind+=2))[1];
			ip.tlen=Create.hex2int(s.substring(ind,ind+=4));
//			System.out.println("ttttes3");
			ip.iden=s.substring(ind,ind+=4);
//			System.out.println("ttttes3");
			ip.flags=s.substring(ind,ind+=4);
//			System.out.println("ttttes3");
			ip.ttl=Create.hex2int(s.substring(ind,ind+=2));
//			System.out.println("ttttes3");
			String protocol=s.substring(ind,ind+=2);
			System.out.println("prottttttttttttttttttttttttttt"+protocol+" "+roulette(Integer.parseInt(protocol,16)));
			ip.protocol=roulette(Integer.parseInt(protocol,16));
			ip.hc=s.substring(ind,ind+=4);
			ip.source=InetAddress.getByAddress(Create.hex2bin(s.substring(ind,ind+=8))).getHostAddress();
			ip.dest=InetAddress.getByAddress(Create.hex2bin(s.substring(ind,ind+=8))).getHostAddress();
			exp+=ip.makeString();
			
			switch(ip.protocol) {
			case "UDP":
				UDP udp=new UDP(String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),s.substring(ind,ind+=4));
				exp+=udp.makeString();
				summary="port "+udp.fport+" -> "+udp.tport;
				break;
//			default:System.exit(-1);
			}
			System.out.println(exp);
			win[1]=d.toString();
			win[2]=ip.source;
			win[3]=ip.dest;
			win[4]=ip.protocol;
			win[5]=String.valueOf(ip.tlen);
			win[6]=summary;
			break;
		case "IPv6":
			IPv6 ip6=new IPv6();
			String vr=Integer.toBinaryString(Integer.parseInt(s.substring(ind,ind+=2),16));
//			System.out.println("ver:"+vl.substring(0,3));
//			System.out.println("ver:"+vl.substring(3,7));
			ip6.version=Integer.toString(Integer.parseInt(vr.substring(0,3),2),10);
			ip6.plen=Integer.toString(Integer.parseInt(s.substring(ind,ind+=4),16));
			ip6.nh=roulette(Integer.parseInt(s.substring(ind,ind+=2),10));
			ip6.hl=Integer.toString(Integer.parseInt(s.substring(ind,ind+=2),16));
			ip6.source=InetAddress.getByName(iper(s.substring(ind,ind+=32))).getHostAddress();
			ip6.dest=InetAddress.getByName(iper(s.substring(ind,ind+=32))).getHostName();
			ip6.show();
			System.exit(-1);
		default :
			win[1]=d.toString();
			win[2]=fMac;
			win[3]=tMac;
			win[4]=this.type;
			win[5]="60";
			win[6]=summary;
		}
	}
	boolean beq(byte[] a,byte[] b) {
		if(a.length!=b.length)return false;
		for(int i=0;i<a.length;i++) {
//			System.out.println("a:"+a[i]+" b:"+b[i]);
			if(!new Byte(a[i]).equals(new Byte(b[i])))return false;
		}
		return true;
	}
	boolean beq(byte[] a,String s) {
		byte[] b=Create.hex2bin(s);
		return beq(a,b);
	}
	String slot(byte[] type) {
		if(beq(type,"0800"))return "IPv4";
		else if(beq(type,"0800"))return "IPv4";
		else if(beq(type,"0806"))return "ARP";
		else if(beq(type,"8035"))return "RARP";
		else if(beq(type,"805b"))return "VMTP";
		else if(beq(type,"809b"))return "AT";
		else if(beq(type,"80F3"))return "AARP";
		else if(beq(type,"8137"))return "IPX";
		else if(beq(type,"814c"))return "SNMP";
		else if(beq(type,"8191"))return "NB";
		else if(beq(type,"817d"))return "XTP";
		else if(beq(type,"86dd"))return "IPv6";
		else if(beq(type,"8863"))return "PPoE";
		else if(beq(type,"8864"))return "PPoE";
		else if(beq(type,"888e"))return "EAP";
//		else if(beq(type,"8899"))return "LoopSearch";
		else if(beq(type,"9000"))return "LoopBack";
		else {
			String s="";
//			for(int i=0;i<type.length;i++) {
				s+=String.valueOf(Create.bin2hex(type));
//			}
			return s;
		}
	}
	String roulette(int v) {
		switch(v) {
		case 0: return "IP";
		case 1: return "ICMP";
		case 3: return "GGP";
		case 6: return "TCP";
		case 8: return "EGP";
		case 12 :return "PUP";
		case 17 :return "UDP";
		case 20 :return "HMP";
		case 22 :return "XNS-IDP";
		case 77 :return "RDP";
		case 66 :return "RVD";
		default: return String.valueOf(v);
		}
	}
	String hexr(String s) {
		String a="";
		for(int i=0;i<s.length();i+=2) {
			a+=s.substring(i,i+2)+":";
		}
		return a.substring(0,a.length()-1);
	}
	String iper(String s) {
		String a="";
		for(int i=0;i<s.length();i+=4) {
			a+=s.substring(i,i+2)+":";
		}
		return a.substring(0,a.length()-1);
	}
}*/














/*
 * 
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:747e
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:6504
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084f76d00003f1122d9c0a86302c0a87ccf0035cff60070fe7c926785830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:f76d
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:22d9
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a747f400040116501c0a87ccfc0a86302ecaf0035003624959804010000010000000000000332323003313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:747f
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:6501
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086f76e00003f1122d6c0a86302c0a87ccf0035ecaf0072a7ed9804858300010000000100000332323003313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:f76e
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:22d6
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a74814000401164ffc0a87ccfc0a86302909d00350036df7c382b010000010000000000000332333403313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:7481
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:64ff
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086f77000003f1122d4c0a86302c0a87ccf0035909d007262d5382b858300010000000100000332333403313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:f770
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:22d4
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a74824000401164fec0a87ccfc0a86302d080003500364c838a3c010000010000000000000332343903313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:7482
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:64fe
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086f77100003f1122d3c0a86302c0a87ccf0035d0800072cfdb8a3c858300010000000100000332343903313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:f771
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:22d3
Source:192.168.99.2
Destination:192.168.124.207





sum:d8:cb:8a:c4:4f:f3 -> ff:ff:ff:ff:ff:ff
ffffffffffffd8cb8ac44ff308060001080006040001d8cb8ac44ff3c0a87cea000000000000c0a87cf9000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.234
smac:d8cb8ac44ff3
dmac:000000000000
sip:c4:192.168.124.234
dip:192.168.124.249
null
Ethernet Frame info
Destination:ffffffffffff
Source:d8cb8ac44ff3
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:d8cb8ac44ff3
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.234
Target IP Adress:192.168.124.249





sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899235e2075a0aa1900268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923f8aff9db87ce00268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e8899236363cda994e500268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899235760b73f054700268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923ca97c269288100268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923c6c79b5329ca00268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923056d4662876200268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923d27c3ff64bf300268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a75a24000401163dec0a87ccfc0a86302cd2400350036ea9ff080010000010000000000000332333403313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:75a2
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:63de
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086f77e00003f1122c6c0a86302c0a87ccf0035cd2400726df8f080858300010000000100000332333403313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:f77e
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:22c6
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a75a34000401163ddc0a87ccfc0a8630288b4003500363a2ae461010000010000000000000332343903313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:75a3
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:63dd
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086f77f00003f1122c5c0a86302c0a87ccf003588b40072bd82e461858300010000000100000332343903313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:f77f
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:22c5
Source:192.168.99.2
Destination:192.168.124.207





sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b888992368a84ea7dce400268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a8899230ada8cc50ec400268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923962ff250284b00268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c78899234ec2bd7ee2a900268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899235e2075a0aa1900268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923598d9f074d5300268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923d27c3ff64bf300268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899235760b73f054700268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899239c75d4b8f2c400268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:1a:eb:54:e8:2f -> ff:ff:ff:ff:ff:ff
ffffffffffff001aeb54e82f08060001080006040001001aeb54e82fc0a87c06000000000000c0a87c01000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.6
smac:001aeb54e82f
dmac:000000000000
sip:c4:192.168.124.6
dip:gateway
null
Ethernet Frame info
Destination:ffffffffffff
Source:001aeb54e82f
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:001aeb54e82f
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.6
Target IP Adress:gateway





sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923c6c79b5329ca00268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923056d4662876200268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923c04fe34d648d00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:1a:eb:54:e7:94 -> ff:ff:ff:ff:ff:ff
ffffffffffff001aeb54e79408060001080006040001001aeb54e794c0a87c03000000000000c0a87c01000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.3
smac:001aeb54e794
dmac:000000000000
sip:c4:192.168.124.3
dip:gateway
null
Ethernet Frame info
Destination:ffffffffffff
Source:001aeb54e794
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:001aeb54e794
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.3
Target IP Adress:gateway





sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b888992368a84ea7dce400268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a8899230ada8cc50ec400268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923952f84d2510300268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c78899234ec2bd7ee2a900268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048811640004011586cc0a87ccfc0a86302e708003500340c6dea0301000001000000000000013603313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:8116
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:586c
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084fa7700003f111fcfc0a86302c0a87ccf0035e70800708fc9ea0385830001000000010000013603313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:fa77
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1fcf
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048811740004011586bc0a87ccfc0a86302b20c00350034df664c0b01000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:8117
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:586b
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084fa7800003f111fcec0a86302c0a87ccf0035b20c007062c34c0b85830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:fa78
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1fce
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048811840004011586ac0a87ccfc0a86302b6b3003500348426a2a201000001000000000000013303313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:8118
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:586a
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084fa7900003f111fcdc0a86302c0a87ccf0035b6b300700783a2a285830001000000010000013303313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:fa79
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1fcd
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac454720800450000488119400040115869c0a87ccfc0a86302877100350034c7178ef501000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:8119
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:5869
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084fa7a00003f111fccc0a86302c0a87ccf0035877100704a748ef585830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:fa7a
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1fcc
Source:192.168.99.2
Destination:192.168.124.207





sum:d8:cb:8a:c4:4f:f3 -> ff:ff:ff:ff:ff:ff
ffffffffffffd8cb8ac44ff308060001080006040001d8cb8ac44ff3c0a87cea000000000000c0a87cf9000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.234
smac:d8cb8ac44ff3
dmac:000000000000
sip:c4:192.168.124.234
dip:192.168.124.249
null
Ethernet Frame info
Destination:ffffffffffff
Source:d8cb8ac44ff3
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:d8cb8ac44ff3
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.234
Target IP Adress:192.168.124.249





sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899235e2075a0aa1900268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923598d9f074d5300268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923d27c3ff64bf300268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899235760b73f054700268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899239c75d4b8f2c400268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004c13f9400040117649c0a87ccfd2ada039b5a0007b0038dcff230207ec000004480000000b85f3eef4dff3ec7c88ea0666dff3ec7a1819953ddff3ec7a19ec2cb3dff3ecfa5ada077ctypes:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004c
Identification:13f9
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:7649
Source:192.168.124.207
Destination:210.173.160.57







sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045c0004c000040003b118e82d2ada039c0a87ccf007bb5a000385d2f240207e800000cc800000d5485f3ec11dff3ea12308048ccdff3ecfa5ada077cdff3ecfa5d34ebd3dff3ecfa5d35d114types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0xc0
Total length:004c
Identification:0000
Flags:0x4000
Time to live:3b
Protocol:11
Heder check sum:8e82
Source:210.173.160.57
Destination:192.168.124.207





sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923c6c79b5329ca00268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a81c24000401157bec0a87ccfc0a86302a22b003500366fe09639010000010000000000000332333403313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:81c2
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:57be
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086fd5600003f111ceec0a86302c0a87ccf0035a22b0072f3389639858300010000000100000332333403313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:fd56
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1cee
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a81c34000401157bdc0a87ccfc0a86302e16c003500360fadb626010000010000000000000332343903313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:81c3
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:57bd
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086fd5700003f111cedc0a86302c0a87ccf0035e16c00729305b626858300010000000100000332343903313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:fd57
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1ced
Source:192.168.99.2
Destination:192.168.124.207





sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923056d4662876200268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923c04fe34d648d00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:d8:cb:8a:c4:4f:f3 -> ff:ff:ff:ff:ff:ff
ffffffffffffd8cb8ac44ff308060001080006040001d8cb8ac44ff3c0a87cea000000000000c0a87cf9000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.234
smac:d8cb8ac44ff3
dmac:000000000000
sip:c4:192.168.124.234
dip:192.168.124.249
null
Ethernet Frame info
Destination:ffffffffffff
Source:d8cb8ac44ff3
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:d8cb8ac44ff3
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.234
Target IP Adress:192.168.124.249





sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b888992355165305c47700268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a823440004011574cc0a87ccfc0a86302de4f003500361cf6acff010000010000000000000332333403313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:8234
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:574c
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086fe6200003f111be2c0a86302c0a87ccf0035de4f0072a04eacff858300010000000100000332333403313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:fe62
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1be2
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a823540004011574bc0a87ccfc0a86302832f00350036d7334cdd010000010000000000000332343903313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:8235
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:574b
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086fe6300003f111be1c0a86302c0a87ccf0035832f00725a8c4cdd858300010000000100000332343903313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:fe63
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1be1
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004c31a54000401198fac0a87ccfcab567d48565007b00383481230207ec000004480000000b85f3eef4dff3ec7c88ea0666dff3ec791356f6bddff3ec79157f7354dff3ecfad19a0ae3types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004c
Identification:31a5
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:98fa
Source:192.168.124.207
Destination:202.181.103.212







sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045c0004c000040003611d3dfcab567d4c0a87ccf007b856500381170240207eb000000890000099485f3eea4dff3e53f36a0ab6ddff3ecfad19a0ae3dff3ecfad3bbccd5dff3ecfad3c2eea8types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0xc0
Total length:004c
Identification:0000
Flags:0x4000
Time to live:36
Protocol:11
Heder check sum:d3df
Source:202.181.103.212
Destination:192.168.124.207





sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a8899230ada8cc50ec400268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923952f84d2510300268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992336e9019004fd00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch












































sum:00:c0:b7:b8:67:53 -> ff:ff:ff:ff:ff:ff
ffffffffffff00c0b7b867530800450002a5000100004011fde9c0a87c0dc0a87cff92af0bec029100004d415354415455530a3c424f44593e0a4d563d76312e372e300a50433d3139322e3136382e3132342e31330a4d413d30302043302042372042382036372035330a44543d30312f32342f323031390a544d3d31363a35313a32330a53523d31300a53553d34333935443046330a52443d393532310a54413d3139322e3136382e3132342e3235350a55433d310a53443d300a534d3d320a534e303d555053204f75746c6574730a534e313d4f75746c65742047726f757020310a5347303d310a5347313d310a534d303d3132300a534d313d3132300a5344303d300a5344313d300a35433d31362e38390a34463d3130332e35390a35313d30380a37453d30300a33453d0a34433d3130332e35390a35303d31392e35300a34333d32302e31380a37383d31322f31382f323031330a36413d303035390a34373d530a36333d4150435550530a36363d3130302e30300a35383d4f4b0a33393d46460a32373d30300a33383d30300a36453d41533133353131313335343220200a36443d31322f31382f323031330a36323d5550532030382e3820284944313829200a30313d536d6172742d55505301313530302020202020202020202020202020202020200a32463d322e35300a34323d32372e32350a34363d36302e30300a34443d3130332e35390a34453d3130332e35390a34353d3333360a37353d0a36433d0a36353d0a36463d3130300a37313d320a36423d4f0a37303d3132300a37323d31300a383145323d0a30353d30300a30393d36302e30300a49303d300a53483d30323337414133313034373934333444333743363546393141443239324439450a4d443d61323438366432353432613435313262313135326463326265633038623733340a3c2f424f44593e0atypes:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:ffffffffffff
Source:00c0b7b86753
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:02a5
Identification:0001
Flags:0x0000
Time to live:40
Protocol:11
Heder check sum:fde9
Source:192.168.124.13
Destination:192.168.124.255





sum:d8:cb:8a:c4:4f:f3 -> ff:ff:ff:ff:ff:ff
ffffffffffffd8cb8ac44ff308060001080006040001d8cb8ac44ff3c0a87cea000000000000c0a87cf9000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.234
smac:d8cb8ac44ff3
dmac:000000000000
sip:c4:192.168.124.234
dip:192.168.124.249
null
Ethernet Frame info
Destination:ffffffffffff
Source:d8cb8ac44ff3
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:d8cb8ac44ff3
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.234
Target IP Adress:192.168.124.249





sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899235e2075a0aa1900268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a867f400040115301c0a87ccfc0a86302dedc00350036e2fbe66c010000010000000000000332333403313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:867f
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:5301
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086018600003f1118bfc0a86302c0a87ccf0035dedc00726654e66c858300010000000100000332333403313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:0186
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:18bf
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a8680400040115300c0a87ccfc0a86302e4500035003696002cef010000010000000000000332343903313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:8680
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:5300
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086018700003f1118bec0a86302c0a87ccf0035e450007219592cef858300010000000100000332343903313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:0187
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:18be
Source:192.168.99.2
Destination:192.168.124.207





sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923598d9f074d5300268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923d27c3ff64bf300268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899235760b73f054700268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899239c75d4b8f2c400268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923d27c3ff64bf300268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f8899233972b94d851e00268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923c04fe34d648d00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b888992355165305c47700268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a8899230ada8cc50ec400268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923952f84d2510300268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992336e9019004fd00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004caaac40004011dd94c0a87ccf85f3eef49f77007b0038b383230207ec000004480000000b85f3eef4dff3ec7c88ea0666dff3ec7c88ec3a57dff3ec7c8b0dd722dff3ecfdb7e2b692types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004c
Identification:aaac
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:dd94
Source:192.168.124.207
Destination:133.243.238.244







sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c008004500004caaac40002e11ef9485f3eef4c0a87ccf007b9f770038a5b1240107ec00000000000000004e494354dff3ecfd00000000dff3ecfdb7e2b692dff3ecfdba0392f4dff3ecfdba03a0b6types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004c
Identification:aaac
Flags:0x4000
Time to live:2e
Protocol:11
Heder check sum:ef94
Source:133.243.238.244
Destination:192.168.124.207





sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923fa45909a65fd00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923598d9f074d5300268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch


^C[root@localhost syunn]# java -jar satou.jar
ttt
ttt
not nulltttttttttttttttttttttttttttttttttttttttttttt



sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899239a360dfee09200268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c7889923735379bef9c300268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899238bae5752dc7600268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b28899239edba54b943300268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923154bdf8724c800268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c8889923e5db258d2f3900268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899238618920f3bbb00268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923c04fe34d648d00268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f8899238cac0415cc1e00268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c98899235e2075a0aa1900268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923815586c1b17000268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a8899238cac0415cc1e00268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch





sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:50:39
d8cb8ac45039a0f8498fb8c0080045000034127940007f06fa53ac16056dc0a87ccbca3b1e008925b6f8000000008002faf05cce0000020405b40103030801010402types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45039
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0034
Identification:1279
Flags:0x4000
Time to live:7f
Protocol:06
Heder check sum:fa53
Source:172.22.5.109
Destination:192.168.124.203





sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899239a360dfee09200268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992398afaadf7e6f00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899238bae5752dc7600268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b28899239edba54b943300268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923154bdf8724c800268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c8889923e5db258d2f3900268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899238618920f3bbb00268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c68899232a97bf0e499000268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923d30525fad97c00268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c98899235e2075a0aa1900268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923815586c1b17000268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a8899238cac0415cc1e00268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899239a360dfee09200268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992398afaadf7e6f00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923bc5648646e0d00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b28899239edba54b943300268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923154bdf8724c800268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c8889923be362d8ec31800268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899238618920f3bbb00268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch





sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:50:39
d8cb8ac45039a0f8498fb8c0080045000034127b40007f06fa51ac16056dc0a87ccbca3b1e008925b6f8000000008002faf05cce0000020405b40103030801010402types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45039
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0034
Identification:127b
Flags:0x4000
Time to live:7f
Protocol:06
Heder check sum:fa51
Source:172.22.5.109
Destination:192.168.124.203





sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c68899232a97bf0e499000268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923d30525fad97c00268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch





sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:50:3e
d8cb8ac4503ea0f8498fb8c00800450000342c5440007f06e230ac1603b0c0a87cd0cbb51e008428cf09000000008002faf049f80000020405b40103030801010402types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac4503e
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0034
Identification:2c54
Flags:0x4000
Time to live:7f
Protocol:06
Heder check sum:e230
Source:172.22.3.176
Destination:192.168.124.208





sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c98899235e2075a0aa1900268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923815586c1b17000268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a889923a60a4bf5b2f800268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899239a360dfee09200268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992398afaadf7e6f00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:70:db:98:fc:f2:8d -> d8:cb:8a:c4:54:72
d8cb8ac4547270db98fcf28d0806000108000604000170db98fcf28d00000000d8cb8ac45472c0a87ccf000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres0.0.0.0
smac:70db98fcf28d
dmac:d8cb8ac45472
sip:c4:0.0.0.0
dip:192.168.124.207
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:70db98fcf28d
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:70db98fcf28d
Target Mac Adress:d8cb8ac45472
Sender IP Adress:0.0.0.0
Target IP Adress:192.168.124.207




sum:d8:cb:8a:c4:54:72 -> 70:db:98:fc:f2:8d
70db98fcf28dd8cb8ac4547208060001080006040002d8cb8ac45472c0a87ccf70db98fcf28d00000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:reply
adres192.168.124.207
smac:d8cb8ac45472
dmac:70db98fcf28d
sip:c4:192.168.124.207
dip:0.0.0.0
null
Ethernet Frame info
Destination:70db98fcf28d
Source:d8cb8ac45472
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:reply
Sender Mac Adress:d8cb8ac45472
Target Mac Adress:70db98fcf28d
Sender IP Adress:192.168.124.207
Target IP Adress:0.0.0.0





sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923bc5648646e0d00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b288992346d4651ddc7700268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e8899235e2075a0aa1900268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c8889923be362d8ec31800268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923fca20ee9bff700268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c68899232a97bf0e499000268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch





sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000042b25e40004011272ac0a87ccfc0a86302aef80035002e2f97a69d01000001000000000000013001300130013007696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0042
Identification:b25e
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:272a
Source:192.168.124.207
Destination:192.168.99.2










sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000073054a00003f11150ec0a86302c0a87ccf0035aef8005f9381a69d85830001000000010000013001300130013007696e2d61646472046172706100000c0001c0120006000100002a300025c01205726e616d6507696e76616c696400000000000001518000000e1000093a8000002a30types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0073
Identification:054a
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:150e
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004ab26240004011271ec0a87ccfc0a86302a97e00350036834c7e77010000010000000000000332303703313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:b262
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:271e
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086054e00003f1114f7c0a86302c0a87ccf0035a97e007206a57e77858300010000000100000332303703313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:054e
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:14f7
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004ab26440004011271cc0a87ccfc0a86302b6ee003500368d5d66f6010000010000000000000332303703313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:b264
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:271c
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086054f00003f1114f6c0a86302c0a87ccf0035b6ee007210b666f6858300010000000100000332303703313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:054f
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:14f6
Source:192.168.99.2
Destination:192.168.124.207






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000042b265400040112723c0a87ccfc0a86302d7bb0035002e0b40a23101000001000000000000013001300130013007696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0042
Identification:b265
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:2723
Source:192.168.124.207
Destination:192.168.99.2










sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000073055000003f111508c0a86302c0a87ccf0035d7bb005f6f2aa23185830001000000010000013001300130013007696e2d61646472046172706100000c0001c0120006000100002a300025c01205726e616d6507696e76616c696400000000000001518000000e1000093a8000002a30types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0073
Identification:0550
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:1508
Source:192.168.99.2
Destination:192.168.124.207





sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923d30525fad97c00268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923fa45909a65fd00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923815586c1b17000268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a889923a60a4bf5b2f800268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899230c31241e777600268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992398afaadf7e6f00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923bc5648646e0d00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b288992346d4651ddc7700268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e8899235e2075a0aa1900268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c8889923be362d8ec31800268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923fca20ee9bff700268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c68899232a97bf0e499000268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923d30525fad97c00268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923fa45909a65fd00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923b67d14b7965000268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:70:db:98:fc:f2:8d -> 00:26:87:16:a5:c7
00268716a5c770db98fcf28d888e03000004040100040000000000000000000000000000000000000000000000000000000000000000000000000000types:888e
type:-120 -114 2
8=0
type:888e




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a889923a60a4bf5b2f800268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899230c31241e777600268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992322a8c727985400268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923bc5648646e0d00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b288992346d4651ddc7700268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e8899235e2075a0aa1900268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c8889923be362d8ec31800268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923fca20ee9bff700268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch





sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:50:39
d8cb8ac45039a0f8498fb8c0080045000034127d40007f06fa4fac16056dc0a87ccbca3b1e008925b6f8000000008002faf05cce0000020405b40103030801010402types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45039
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0034
Identification:127d
Flags:0x4000
Time to live:7f
Protocol:06
Heder check sum:fa4f
Source:172.22.5.109
Destination:192.168.124.203





sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c68899235e2075a0aa1900268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f88992332554d26ead300268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923fa45909a65fd00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923b67d14b7965000268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a889923a60a4bf5b2f800268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:a0:f8:49:8f:b8:c0 -> ff:ff:ff:ff:ff:ff
ffffffffffffa0f8498fb8c008060001080006040001a0f8498fb8c0c0a87c01000000000000c0a87cef000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adresgateway
smac:a0f8498fb8c0
dmac:000000000000
sip:c4:gateway
dip:192.168.124.239
null
Ethernet Frame info
Destination:ffffffffffff
Source:a0f8498fb8c0
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:a0f8498fb8c0
Target Mac Adress:000000000000
Sender IP Adress:gateway
Target IP Adress:192.168.124.239





sum:a0:f8:49:8f:b8:c0 -> ff:ff:ff:ff:ff:ff
ffffffffffffa0f8498fb8c008060001080006040001a0f8498fb8c0c0a87c01000000000000c0a87ce6000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adresgateway
smac:a0f8498fb8c0
dmac:000000000000
sip:c4:gateway
dip:192.168.124.230
null
Ethernet Frame info
Destination:ffffffffffff
Source:a0f8498fb8c0
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:a0f8498fb8c0
Target Mac Adress:000000000000
Sender IP Adress:gateway
Target IP Adress:192.168.124.230





sum:a0:f8:49:8f:b8:c0 -> ff:ff:ff:ff:ff:ff
ffffffffffffa0f8498fb8c008060001080006040001a0f8498fb8c0c0a87c01000000000000c0a87cd6000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adresgateway
smac:a0f8498fb8c0
dmac:000000000000
sip:c4:gateway
dip:192.168.124.214
null
Ethernet Frame info
Destination:ffffffffffff
Source:a0f8498fb8c0
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:a0f8498fb8c0
Target Mac Adress:000000000000
Sender IP Adress:gateway
Target IP Adress:192.168.124.214





sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899230c31241e777600268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992322a8c727985400268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048ba1e400040111f64c0a87ccfc0a86302c43e003500347ee59a5a01000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:ba1e
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f64
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084101100003f110a36c0a86302c0a87ccf0035c43e007002429a5a85830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:1011
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a36
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000043ba1f400040111f68c0a87ccfc0a86302dbe30035002f1b4a6ee4010000010000000000000767617465776179076f6974612d6374026163026a700000010001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0043
Identification:ba1f
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f68
Source:192.168.124.207
Destination:192.168.99.2







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000043ba20400040111f67c0a87ccfc0a86302dbe30035002f9244dce9010000010000000000000767617465776179076f6974612d6374026163026a7000001c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0043
Identification:ba20
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f67
Source:192.168.124.207
Destination:192.168.99.2









sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000072101200003f110a47c0a86302c0a87ccf0035dbe3005ec1db6ee4858300010000000100000767617465776179076f6974612d6374026163026a700000010001c01400060001000007080023056b646e7332c01404726f6f74c0147849ce740000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0072
Identification:1012
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a47
Source:192.168.99.2
Destination:192.168.124.207









sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000072101300003f110a46c0a86302c0a87ccf0035dbe3005e38d6dce9858300010000000100000767617465776179076f6974612d6374026163026a7000001c0001c01400060001000007080023056b646e7332c01404726f6f74c0147849ce740000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0072
Identification:1013
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a46
Source:192.168.99.2
Destination:192.168.124.207






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000035ba21400040111f74c0a87ccfc0a86302ce4000350021148d88b90100000100000000000007676174657761790000010001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0035
Identification:ba21
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f74
Source:192.168.124.207
Destination:192.168.99.2






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000035ba22400040111f73c0a87ccfc0a86302ce40003500217f8802be01000001000000000000076761746577617900001c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0035
Identification:ba22
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f73
Source:192.168.124.207
Destination:192.168.99.2










sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000080101400003f110a37c0a86302c0a87ccf0035ce40006cfca088b98183000100000001000007676174657761790000010001000006000100000327004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d007857af30000007080000038400093a8000015180types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0080
Identification:1014
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a37
Source:192.168.99.2
Destination:192.168.124.207










sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000080101500003f110a36c0a86302c0a87ccf0035ce40006c679c02be81830001000000010000076761746577617900001c0001000006000100000327004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d007857af30000007080000038400093a8000015180types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0080
Identification:1015
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a36
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004aba23400040111f5dc0a87ccfc0a86302ee4100350036530666f8010000010000000000000332333903313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:ba23
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f5d
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086101600003f110a2fc0a86302c0a87ccf0035ee410072d65e66f8858300010000000100000332333903313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:1016
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a2f
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048ba24400040111f5ec0a87ccfc0a86302df5100350034a7c4566801000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:ba24
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f5e
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084101700003f110a30c0a86302c0a87ccf0035df5100702b21566885830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:1017
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a30
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004aba25400040111f5bc0a87ccfc0a863028baf00350036d9c442d5010000010000000000000332333003313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:ba25
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f5b
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086101800003f110a2dc0a86302c0a87ccf00358baf00725d1d42d5858300010000000100000332333003313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:1018
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a2d
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048ba2b400040111f57c0a87ccfc0a863028497003500347ee5da0101000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:ba2b
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f57
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084101d00003f110a2ac0a86302c0a87ccf0035849700700242da0185830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:101d
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a2a
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004aba2c400040111f54c0a87ccfc0a86302a4e4003500362272e2ee010000010000000000000332313403313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:ba2c
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1f54
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086101e00003f110a27c0a86302c0a87ccf0035a4e40072a5cae2ee858300010000000100000332313403313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:101e
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0a27
Source:192.168.99.2
Destination:192.168.124.207













































sum:00:c0:b7:b8:67:53 -> ff:ff:ff:ff:ff:ff
ffffffffffff00c0b7b867530800450002a5000100004011fde9c0a87c0dc0a87cffdc900bec029100004d415354415455530a3c424f44593e0a4d563d76312e372e300a50433d3139322e3136382e3132342e31330a4d413d30302043302042372042382036372035330a44543d30312f32342f323031390a544d3d31363a35313a34390a53523d31300a53553d34333935444232320a52443d413946410a54413d3139322e3136382e3132342e3235350a55433d310a53443d300a534d3d320a534e303d555053204f75746c6574730a534e313d4f75746c65742047726f757020310a5347303d310a5347313d310a534d303d3132300a534d313d3132300a5344303d300a5344313d300a35433d31362e38390a34463d3130322e38390a35313d30380a37453d30300a33453d0a34433d3130322e38390a35303d31392e35300a34333d32302e31380a37383d31322f31382f323031330a36413d303035390a34373d530a36333d4150435550530a36363d3130302e30300a35383d4f4b0a33393d46460a32373d30300a33383d30300a36453d41533133353131313335343220200a36443d31322f31382f323031330a36323d5550532030382e3820284944313829200a30313d536d6172742d55505301313530302020202020202020202020202020202020200a32463d322e35300a34323d32372e32350a34363d35392e39330a34443d3130322e38390a34453d3130322e38390a34353d3333360a37353d0a36433d0a36353d0a36463d3130300a37313d320a36423d4f0a37303d3132300a37323d31300a383145323d0a30353d30300a30393d35392e39330a49303d300a53483d34363442374530354232333744373945394537433939414443333539393633330a4d443d37663064343035636666613336343563383532366339616137373566626438370a3c2f424f44593e0atypes:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:ffffffffffff
Source:00c0b7b86753
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:02a5
Identification:0001
Flags:0x0000
Time to live:40
Protocol:11
Heder check sum:fde9
Source:192.168.124.13
Destination:192.168.124.255





sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899232f54a176014d00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b288992346d4651ddc7700268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e8899235e2075a0aa1900268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899234fd6abe9a28400268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923fca20ee9bff700268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c68899235e2075a0aa1900268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f88992332554d26ead300268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923fa45909a65fd00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923b67d14b7965000268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a88992332554d26ead300268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899230c31241e777600268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992322a8c727985400268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899232f54a176014d00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923a8d08b44598000268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923fd22c84d32fe00268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899234fd6abe9a28400268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923d6c83c93b10300268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c68899235e2075a0aa1900268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f88992332554d26ead300268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923175caea5b8ec00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923b67d14b7965000268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a88992332554d26ead300268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923f9441dd37fef00268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c788992322a8c727985400268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899232f54a176014d00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923a8d08b44598000268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923fd22c84d32fe00268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899234fd6abe9a28400268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923d6c83c93b10300268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c68899235e2075a0aa1900268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f88992332554d26ead300268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch



sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208060001080006040001d8cb8ac45472c0a87ccf000000000000c0a87c01types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.207
smac:d8cb8ac45472
dmac:000000000000
sip:c4:192.168.124.207
dip:gateway
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:d8cb8ac45472
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.207
Target IP Adress:gateway





sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c008060001080006040002a0f8498fb8c0c0a87c01d8cb8ac45472c0a87ccf000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:reply
adresgateway
smac:a0f8498fb8c0
dmac:d8cb8ac45472
sip:c4:gateway
dip:192.168.124.207
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:reply
Sender Mac Adress:a0f8498fb8c0
Target Mac Adress:d8cb8ac45472
Sender IP Adress:gateway
Target IP Adress:192.168.124.207





sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923175caea5b8ec00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b88899230059b0be387b00268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a88992332554d26ead300268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923f9441dd37fef00268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c7889923af84991f74f700268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4848899232f54a176014d00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923a8d08b44598000268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923fd22c84d32fe00268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899234fd6abe9a28400268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923d6c83c93b10300268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004ad0fc400040110884c0a87ccfc0a86302b0050035003634c3c679010000010000000000000332303703313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:d0fc
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:0884
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086121800003f11082dc0a86302c0a87ccf0035b0050072b81bc679858300010000000100000332303703313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:1218
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:082d
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048d0fd400040110885c0a87ccfc0a86302811400350034440f185b01000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:d0fd
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:0885
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084121900003f11082ec0a86302c0a87ccf003581140070c76b185b85830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:1219
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:082e
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048d0ff400040110883c0a87ccfc0a86302e49700350034844374a301000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:d0ff
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:0883
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084121b00003f11082cc0a86302c0a87ccf0035e497007007a074a385830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:121b
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:082c
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004ad100400040110880c0a87ccfc0a86302b66b00350036526fa267010000010000000000000332303703313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:d100
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:0880
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086121c00003f110829c0a86302c0a87ccf0035b66b0072d5c7a267858300010000000100000332303703313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:121c
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:0829
Source:192.168.99.2
Destination:192.168.124.207





sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923fa45909a65fd00268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923ce4e9aec37e700268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923175caea5b8ec00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:a0:f8:49:8f:b8:c0 -> ff:ff:ff:ff:ff:ff
ffffffffffffa0f8498fb8c008060001080006040001a0f8498fb8c0c0a87c01000000000000c0a87cdc000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adresgateway
smac:a0f8498fb8c0
dmac:000000000000
sip:c4:gateway
dip:192.168.124.220
null
Ethernet Frame info
Destination:ffffffffffff
Source:a0f8498fb8c0
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:a0f8498fb8c0
Target Mac Adress:000000000000
Sender IP Adress:gateway
Target IP Adress:192.168.124.220





sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b88899230059b0be387b00268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a88992332554d26ead300268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923f9441dd37fef00268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c7889923af84991f74f700268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048d581400040110401c0a87ccfc0a863028e0a00350034d48c7ae701000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:d581
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:0401
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000084127200003f1107d5c0a86302c0a87ccf00358e0a007057e97ae785830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:1272
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:07d5
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004ad5824000401103fec0a87ccfc0a863028e9f0035003680609a49010000010000000000000332323003313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:d582
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:03fe
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086127300003f1107d2c0a86302c0a87ccf00358e9f007203b99a49858300010000000100000332323003313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:1273
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:07d2
Source:192.168.99.2
Destination:192.168.124.207





sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923e38994bd19fa00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923a8d08b44598000268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923fd22c84d32fe00268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c8889923c39975efc6a400268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923d6c83c93b10300268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923fa45909a65fd00268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923ce4e9aec37e700268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c9889923175caea5b8ec00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b88899230059b0be387b00268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a889923ce4e9aec37e700268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923f9441dd37fef00268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c7889923af84991f74f700268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923e38994bd19fa00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b28899233a6beefdd4be00268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e8899238bae5752dc7600268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c8889923c39975efc6a400268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




^C[root@localhost syunn]# java -jar satou.jar
ttt
ttt
not nulltttttttttttttttttttttttttttttttttttttttttttt



sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923581124ad842c00268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c78899238ec79c876bfa00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923962ff250284b00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:d8:cb:8a:c4:4f:f3 -> ff:ff:ff:ff:ff:ff
ffffffffffffd8cb8ac44ff308060001080006040001d8cb8ac44ff3c0a87cea000000000000c0a87cf9000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.234
smac:d8cb8ac44ff3
dmac:000000000000
sip:c4:192.168.124.234
dip:192.168.124.249
null
Ethernet Frame info
Destination:ffffffffffff
Source:d8cb8ac44ff3
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:d8cb8ac44ff3
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.234
Target IP Adress:192.168.124.249





sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b2889923cf644ba651c900268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923359374ccdd5400268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a490889923495069beb67e00268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899239c1cace49a4c00268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923ee5cb91dd85100268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f88992314ebeeb55b2c00268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c98899238d2f0374d38d00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:d8:cb:8a:c4:4f:f3 -> ff:ff:ff:ff:ff:ff
ffffffffffffd8cb8ac44ff308060001080006040001d8cb8ac44ff3c0a87cea000000000000c0a87cf9000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.234
smac:d8cb8ac44ff3
dmac:000000000000
sip:c4:192.168.124.234
dip:192.168.124.249
null
Ethernet Frame info
Destination:ffffffffffff
Source:d8cb8ac44ff3
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:d8cb8ac44ff3
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.234
Target IP Adress:192.168.124.249







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004abb51400040111e2fc0a87ccfc0a86302b2080035003653fea23e010000010000000000000332333403313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:bb51
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1e2f
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086392b00003f11e119c0a86302c0a87ccf0035b2080072d756a23e858300010000000100000332333403313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:392b
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:e119
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004abb52400040111e2ec0a87ccfc0a86302b25c00350036fbe9f8f9010000010000000000000332343903313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:bb52
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1e2e
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c0080045000086392c00003f11e118c0a86302c0a87ccf0035b25c00727f42f8f9858300010000000100000332343903313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:392c
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:e118
Source:192.168.99.2
Destination:192.168.124.207





sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b8889923c5ea36ed7e0e00268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a88992329d7dd6ab65900268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:a0:f8:49:8f:b8:c0 -> ff:ff:ff:ff:ff:ff
ffffffffffffa0f8498fb8c008060001080006040001a0f8498fb8c0c0a87c01000000000000c0a87cdb000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adresgateway
smac:a0f8498fb8c0
dmac:000000000000
sip:c4:gateway
dip:192.168.124.219
null
Ethernet Frame info
Destination:ffffffffffff
Source:a0f8498fb8c0
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:a0f8498fb8c0
Target Mac Adress:000000000000
Sender IP Adress:gateway
Target IP Adress:192.168.124.219





sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a492889923ba97f398b7d900268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c78899238ec79c876bfa00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004abd78400040111c08c0a87ccfc0a86302ecbe003500368b713015010000010000000000000332333403313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:bd78
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1c08
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000863be700003f11de5dc0a86302c0a87ccf0035ecbe00720eca3015858300010000000100000332333403313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:3be7
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:de5d
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004abd7a400040111c06c0a87ccfc0a86302ec020035003678bc4281010000010000000000000332343903313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:004a
Identification:bd7a
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1c06
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000863be800003f11de5cc0a86302c0a87ccf0035ec020072fc144281858300010000000100000332343903313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0086
Identification:3be8
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:de5c
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000048bd83400040111bffc0a87ccfc0a86302e24d00350034c0953a9b01000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0048
Identification:bd83
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1bff
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000843bea00003f11de5cc0a86302c0a87ccf0035e24d007043f23a9b85830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0084
Identification:3bea
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:de5c
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000043bd84400040111c03c0a87ccfc0a86302d4010035002f2c086608010000010000000000000767617465776179076f6974612d6374026163026a700000010001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0043
Identification:bd84
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1c03
Source:192.168.124.207
Destination:192.168.99.2







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000043bd85400040111c02c0a87ccfc0a86302d4010035002f4701300f010000010000000000000767617465776179076f6974612d6374026163026a7000001c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0043
Identification:bd85
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1c02
Source:192.168.124.207
Destination:192.168.99.2









sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000723beb00003f11de6dc0a86302c0a87ccf0035d401005ed2996608858300010000000100000767617465776179076f6974612d6374026163026a700000010001c01400060001000007080023056b646e7332c01404726f6f74c0147849ce740000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0072
Identification:3beb
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:de6d
Source:192.168.99.2
Destination:192.168.124.207









sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000723bec00003f11de6cc0a86302c0a87ccf0035d401005eed92300f858300010000000100000767617465776179076f6974612d6374026163026a7000001c0001c01400060001000007080023056b646e7332c01404726f6f74c0147849ce740000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0072
Identification:3bec
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:de6c
Source:192.168.99.2
Destination:192.168.124.207






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000035bd86400040111c0fc0a87ccfc0a86302dde5003500218cb600eb0100000100000000000007676174657761790000010001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0035
Identification:bd86
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1c0f
Source:192.168.124.207
Destination:192.168.99.2






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac45472080045000035bd87400040111c0ec0a87ccfc0a86302dde50035002121b050f101000001000000000000076761746577617900001c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0035
Identification:bd87
Flags:0x4000
Time to live:40
Protocol:11
Heder check sum:1c0e
Source:192.168.124.207
Destination:192.168.99.2










sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000803bed00003f11de5dc0a86302c0a87ccf0035dde5006c75e600eb818300010000000100000767617465776179000001000100000600010000020b004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d007857af30000007080000038400093a8000015180types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:0080
Identification:3bed
Flags:0x0000
Time to live:3f
Protocol:11
Heder check sum:de5d
Source:192.168.99.2
Destination:192.168.124.207









^C[root@localhost syunn]# java -jar satou.jar
ttt
ttt
not nulltttttttttttttttttttttttttttttttttttttttttttt



sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48488992336a11c32375b00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b288992360f435a999a900268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923321bb3e2a02500268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899231f2e9086014300268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899239a360dfee09200268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923321bb3e2a02500268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923206620c3539200268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c98899236661856df64c00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b88899232ac8c8bc529800268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:a0:f8:49:8f:b8:c0 -> ff:ff:ff:ff:ff:ff
ffffffffffffa0f8498fb8c008060001080006040001a0f8498fb8c0c0a87c01000000000000c0a87ce4000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adresgateway
smac:a0f8498fb8c0
dmac:000000000000
sip:c4:gateway
dip:192.168.124.228
null
Ethernet Frame info
Destination:ffffffffffff
Source:a0f8498fb8c0
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:a0f8498fb8c0
Target Mac Adress:000000000000
Sender IP Adress:gateway
Target IP Adress:192.168.124.228





sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a889923de4eae177a0700268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:a0:f8:49:8f:b8:c0 -> ff:ff:ff:ff:ff:ff
ffffffffffffa0f8498fb8c008060001080006040001a0f8498fb8c0c0a87c01000000000000c0a87cdc000000000000000000000000000000000000types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adresgateway
smac:a0f8498fb8c0
dmac:000000000000
sip:c4:gateway
dip:192.168.124.220
null
Ethernet Frame info
Destination:ffffffffffff
Source:a0f8498fb8c0
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:a0f8498fb8c0
Target Mac Adress:000000000000
Sender IP Adress:gateway
Target IP Adress:192.168.124.220







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac454720800450000488d9e400040114be4c0a87ccfc0a86302b5d10035003472cdb4df01000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:72
Identification:8d9e
Flags:0x4000
Time to live:64
Protocol:11
Heder check sum:4be4
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000848c4c00003f118dfac0a86302c0a87ccf0035b5d10070f629b4df85830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:132
Identification:8c4c
Flags:0x0000
Time to live:63
Protocol:11
Heder check sum:8dfa
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac454720800450000438d9f400040114be8c0a87ccfc0a86302dfb30035002fed9298cb010000010000000000000767617465776179076f6974612d6374026163026a700000010001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:67
Identification:8d9f
Flags:0x4000
Time to live:64
Protocol:11
Heder check sum:4be8
Source:192.168.124.207
Destination:192.168.99.2







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac454720800450000438da0400040114be7c0a87ccfc0a86302dfb30035002f4e8b1cd3010000010000000000000767617465776179076f6974612d6374026163026a7000001c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:67
Identification:8da0
Flags:0x4000
Time to live:64
Protocol:11
Heder check sum:4be7
Source:192.168.124.207
Destination:192.168.99.2









sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000728c4d00003f118e0bc0a86302c0a87ccf0035dfb3005e942498cb858300010000000100000767617465776179076f6974612d6374026163026a700000010001c01400060001000007080023056b646e7332c01404726f6f74c0147849ce740000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:114
Identification:8c4d
Flags:0x0000
Time to live:63
Protocol:11
Heder check sum:8e0b
Source:192.168.99.2
Destination:192.168.124.207









sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000728c4e00003f118e0ac0a86302c0a87ccf0035dfb3005ef51c1cd3858300010000000100000767617465776179076f6974612d6374026163026a7000001c0001c01400060001000007080023056b646e7332c01404726f6f74c0147849ce740000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:114
Identification:8c4e
Flags:0x0000
Time to live:63
Protocol:11
Heder check sum:8e0a
Source:192.168.99.2
Destination:192.168.124.207






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac454720800450000358da1400040114bf4c0a87ccfc0a86302b10a00350021cb91eeea0100000100000000000007676174657761790000010001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:53
Identification:8da1
Flags:0x4000
Time to live:64
Protocol:11
Heder check sum:4bf4
Source:192.168.124.207
Destination:192.168.99.2






sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac454720800450000358da2400040114bf3c0a87ccfc0a86302b10a003500210e8d90ef01000001000000000000076761746577617900001c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:53
Identification:8da2
Flags:0x4000
Time to live:64
Protocol:11
Heder check sum:4bf3
Source:192.168.124.207
Destination:192.168.99.2










sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000808c4f00003f118dfbc0a86302c0a87ccf0035b10a006cb53deeea818300010000000100000767617465776179000001000100000600010000018f004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d007857af30000007080000038400093a8000015180types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:128
Identification:8c4f
Flags:0x0000
Time to live:63
Protocol:11
Heder check sum:8dfb
Source:192.168.99.2
Destination:192.168.124.207










sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000808c5000003f118dfac0a86302c0a87ccf0035b10a006cf83890ef81830001000000010000076761746577617900001c000100000600010000018f004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d007857af30000007080000038400093a8000015180types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:128
Identification:8c50
Flags:0x0000
Time to live:63
Protocol:11
Heder check sum:8dfa
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a8da3400040114bddc0a87ccfc0a86302b284003500369e4b5871010000010000000000000332323803313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:74
Identification:8da3
Flags:0x4000
Time to live:64
Protocol:11
Heder check sum:4bdd
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000868c5100003f118df3c0a86302c0a87ccf0035b284007221a45871858300010000000100000332323803313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:134
Identification:8c51
Flags:0x0000
Time to live:63
Protocol:11
Heder check sum:8df3
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac454720800450000488da5400040114bddc0a87ccfc0a86302c12e003500344c21d02e01000001000000000000013103313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:72
Identification:8da5
Flags:0x4000
Time to live:64
Protocol:11
Heder check sum:4bdd
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000848c5200003f118df4c0a86302c0a87ccf0035c12e0070cf7dd02e85830001000000010000013103313234033136380331393207696e2d61646472046172706100000c0001c00e00060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c03e780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:132
Identification:8c52
Flags:0x0000
Time to live:63
Protocol:11
Heder check sum:8df4
Source:192.168.99.2
Destination:192.168.124.207







sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208004500004a8da6400040114bdac0a87ccfc0a8630292050035003681019642010000010000000000000332323003313234033136380331393207696e2d61646472046172706100000c0001types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:74
Identification:8da6
Flags:0x4000
Time to live:64
Protocol:11
Heder check sum:4bda
Source:192.168.124.207
Destination:192.168.99.2











sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:54:72
d8cb8ac45472a0f8498fb8c00800450000868c5300003f118df1c0a86302c0a87ccf003592050072045a9642858300010000000100000332323003313234033136380331393207696e2d61646472046172706100000c0001c01000060001000007080030056b646e7332076f6974612d6374026163026a700004726f6f74c040780baf550000a8c000000e100013c68000000708types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac45472
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:134
Identification:8c53
Flags:0x0000
Time to live:63
Protocol:11
Heder check sum:8df1
Source:192.168.99.2
Destination:192.168.124.207





sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a49288992388d42dfe1a0a00268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c78899233d8bc4bf646a00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923b5092f2a1dff00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b288992360f435a999a900268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923321bb3e2a02500268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899231f2e9086014300268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899230c31241e777600268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923321bb3e2a02500268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923206620c3539200268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c98899236661856df64c00268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b88899232ac8c8bc529800268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a889923206620c3539200268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a49288992388d42dfe1a0a00268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c78899233d8bc4bf646a00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923b5092f2a1dff00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b288992381c7091c569c00268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923b330c2b6fb2600268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899232ecdce69eed300268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899230c31241e777600268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c6 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c6889923321bb3e2a02500268716a5c6040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:8f -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a48f889923206620c3539200268716a48f040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c9 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c98899235c9ef89bcd6900268716a5c9040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b88899232ac8c8bc529800268716a4b8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:0a -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a50a889923206620c3539200268716a50a040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch





sum:a0:f8:49:8f:b8:c0 -> d8:cb:8a:c4:50:3e
d8cb8ac4503ea0f8498fb8c0080045000034056040007f060a37ac16029ec0a87cd0cff11e00098b9ae0000000008002faf0f5940000020405b40103030801010402types:0800
type:8 0 2
8=0
type:IPv4
ver:100
ver:0101
ttttes
ttttes2
ttttes3
ttttes3
ttttes3
ttttes3
null
Ethernet Frame info
Destination:d8cb8ac4503e
Source:a0f8498fb8c0
type:IPv4

Internet Protocol Version 4
Version:4
Header length:5
Differentiated Services Field:0x00
Total length:52
Identification:0560
Flags:0x4000
Time to live:127
Protocol:06
Heder check sum:0a37
Source:172.22.2.158
Destination:192.168.124.208





sum:00:26:87:16:a4:92 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4928899233e5d210c028600268716a492040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c7 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c78899233d8bc4bf646a00268716a5c7020000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:84 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a484889923b5092f2a1dff00268716a484040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:b2 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4b288992381c7091c569c00268716a4b2040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:7e -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a47e889923b330c2b6fb2600268716a47e040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a4:90 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a4908899232ecdce69eed300268716a490040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch




sum:00:26:87:16:a5:c8 -> ff:ff:ff:ff:ff:ff
ffffffffffff00268716a5c88899230c31241e777600268716a5c8040000000000000000000000000000000000000000000000000000000000000000types:8899
type:-120 -103 2
8=0
type:LoopSearch



sum:d8:cb:8a:c4:54:72 -> a0:f8:49:8f:b8:c0
a0f8498fb8c0d8cb8ac4547208060001080006040001d8cb8ac45472c0a87ccf000000000000c0a87c01types:0806
type:8 6 2
8=0
type:ARP
htype:0001
protocol:IPv4
opcode:request
adres192.168.124.207
smac:d8cb8ac45472
dmac:000000000000
sip:c4:192.168.124.207
dip:gateway
null
Ethernet Frame info
Destination:a0f8498fb8c0
Source:d8cb8ac45472
type:ARP

Adress resolution protocol
Hardware type:Ethernet
Protocol type:IPv4
Hardware size:06
Protocol size:04
Opcode:request
Sender Mac Adress:d8cb8ac45472
Target Mac Adress:000000000000
Sender IP Adress:192.168.124.207
Target IP Adress:gateway


^C[root@localhost syunn]# ^C
[root@localhost syunn]# 
*/