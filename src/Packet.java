import java.net.Inet6Address;
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
			System.out.println("protcol"+protocol+" "+roulette(Integer.parseInt(protocol,16)));
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
			case "TCP":
				TCP tcp=new TCP();
				tcp.sport=String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16));
				tcp.dport=String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16));
				tcp.snum=s.substring(ind,ind+=8);
				tcp.anum=s.substring(ind,ind+=8);
				tcp.ack=s.substring(ind,ind+=4);
				tcp.wsize=String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16));
				tcp.csum=s.substring(ind,ind+=4);
				tcp.upoint=s.substring(ind,ind+=4);
				exp+=tcp.makeString();
				summary="port "+tcp.sport+" -> "+tcp.dport;
				System.out.println(exp);
				break;
				default:System.out.println(ip.protocol);
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
			String vr=Integer.toBinaryString(Integer.parseInt(s.substring(ind,ind+=8),16));
//			System.out.println("ver:"+vl.substring(0,3));
//			System.out.println("ver:"+vl.substring(3,7));
			ip6.version=Integer.toString(Integer.parseInt(vr.substring(0,3),2),10);
			ip6.plen=Integer.toString(Integer.parseInt(s.substring(ind,ind+=4),16));
			ip6.nh=roulette(Integer.parseInt(s.substring(ind,ind+=2),16));
			ip6.hl=Integer.toString(Integer.parseInt(s.substring(ind,ind+=2),16));
			ip6.source=InetAddress.getByName(iper(s.substring(ind,ind+=32))).getHostName();
			ip6.dest=Inet6Address.getByName(iper(s.substring(ind,ind+=32))).getHostName();
			exp+=ip6.makeString();
			switch(ip6.nh) {
			case "UDP":
				UDP udp=new UDP(String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16)),s.substring(ind,ind+=4));
				exp+=udp.makeString();
				summary="port "+udp.fport+" -> "+udp.tport;
				System.out.println(exp);
				break;

			case "TCP":
				TCP tcp=new TCP();
				tcp.sport=String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16));
				tcp.dport=String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16));
				tcp.snum=s.substring(ind,ind+=8);
				tcp.anum=s.substring(ind,ind+=8);
				tcp.ack=s.substring(ind,ind+=4);
				tcp.wsize=String.valueOf(Integer.parseInt(s.substring(ind,ind+=4),16));
				tcp.csum=s.substring(ind,ind+=4);
				tcp.upoint=s.substring(ind,ind+=4);
				exp+=tcp.makeString();
				summary="port "+tcp.sport+" -> "+tcp.dport;
				System.out.println(exp);
				break;
				default:System.out.println(ip6.nh);
			}
			win[1]=d.toString();
			win[2]=ip6.source;
			win[3]=ip6.dest;
			win[4]="IPv6";
			win[5]=String.valueOf((ip6.plen+ip6.hl));
			win[6]=summary;
			break;
		case "8899":
			win[1]=d.toString();
			win[2]=fMac;
			win[3]=tMac;
			win[4]=this.type;
			win[5]="60";
			win[6]="roopsearch";
			break;
			
			
		default :
			win[1]=d.toString();
			win[2]=fMac;
			win[3]=tMac;
			win[4]=this.type;
			win[5]="60";
			win[6]="default";
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