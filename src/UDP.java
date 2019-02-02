public class UDP {
	String fport,tport,len,csum;
	UDP(String s,String ss,String sss,String ssss){
		fport=s;
		tport=ss;
		len=sss;
		csum=ssss;
	}
	String makeString() {
		return "\n\nUser Datagram Protocol\n"
				+ "Source port:"+fport+""
				+ "\nDestination port:"+tport+""
						+ "\nLength:"+len+""
								+ "\nCheck sum:"+csum;
	}
}
