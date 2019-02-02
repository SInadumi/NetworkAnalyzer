public class IPv6 {
	String version;
	String plen;
	String nh,hl;
	String source,dest;
	String makeString(){
		return "\n\nInternet Protocol ver 6\n"+
				"Version:"+version+
					"\nPayload Length:"+plen
						+"\nNext Header:"+nh
							+"\nHop Limit:"+hl
								+"\nSource Address:"+source
									+"\nDestination Address:"+dest;
	}
}