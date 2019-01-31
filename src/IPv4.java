

public class IPv4 {
	String version;
	String hlen;
	String dsf;
	int tlen;
	String iden;
	String flags;
	int ttl;
	String protocol;
	String hc;
	String source;
	String dest;
	String makeString() {
		String s="";
		s+="\n\nInternet Protocol Version 4\n"
				+ "Version:"+version+"\n"
						+ "Header length:"+hlen+"\n"
								+ "Differentiated Services Field:0x"+dsf+"\n"
										+ "Total length:"+tlen+"\n"
												+ "Identification:"+iden+"\n"
														+ "Flags:"+flags+"\n"
																+ "Time to live:"+ttl+"\n"
																	+ "Protocol:"+protocol+"\n"
																		+ "Heder check sum:"+hc+"\n"
																				+ "Source:"+source+"\n"
																						+ "Destination:"+dest+"\n";
		return s;
	}
}
