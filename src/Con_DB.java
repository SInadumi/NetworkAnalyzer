
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
public class Con_DB {
	Connection conn;
	java.sql.Statement stmt;
	Statement sta;
	
	String sql;
	ResultSet rs;
	public void Open(){//DBhenosetuzoku
		try {
		conn=null;
		
			/*conn=DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/DB_Con", 
					"root", "NETWORK1@root");			*/			//windows name root@localhost pz NETWORK@1root
			//pz -> NA1@root 
			conn=DriverManager.getConnection("jdbc:mysql://127.0.0.1:3306/DB_Con", 
					"root", "NA1@root");	
			stmt =conn.createStatement();
			sta=conn.createStatement();
			System.out.println("----------接続成功-----------");
		}catch(SQLException e) {
			System.out.println("*****connerr*****");
			e.printStackTrace();
		}
	}
	public void Sql_In(int id,String time,String to,String from,String protocol,int length,String info) throws Exception{//table he ataiwo ireruyo
		sql="insert into packet(Id,GetDate,Packet_To,Packet_From,Packet_Protocol,Packet_Length,Packet_Info)"
				+ " values("+id+",'"+time+"','"+to+"','"+from+"','"+protocol+"',"+length+",'"+info+"')";
		int num=sta.executeUpdate(sql);
		System.out.println("更新された行="+num);
		
	}
	public void Sql_clear() throws SQLException {
		sta.executeUpdate("truncate table packet;");
	}
	public void Sql_Out()throws Exception {
		/*Packet instance printout*/
		String[] to=new String[100];
		String[] id=new String[100];
		String[] from=new String[100];
		String[] protocol=new String[100];
		sql="select Id,GetDate,Packet_To,Packet_From,Packet_Protocol,Packet_Length,Packet_Info from DB_Con";
		rs=stmt.executeQuery(sql);
		int i=0;
		while(rs.next()) {
			System.out.println("id:"+rs.getString("Id"));
			System.out.println("date:"+rs.getString("GetDate"));
			System.out.println("to:"+rs.getString("Packet_To"));
			System.out.println("from:"+rs.getString("Packet_From"));
			System.out.println("protocol:"+rs.getString("Packet_Protocol"));
			System.out.println("length:"+rs.getString("Packet_length"));
			System.out.println("info:"+rs.getString("Packet_Info"));
			to[i]=rs.getString("Packet_To");
			id[i]=rs.getString("Id");
			from[i]=rs.getString("Packet_From");
			protocol[i]=rs.getString("Packet_Protocol");
			i++;
		}
	}
	public void Fin() {
		try {
            if (null != conn) {
                conn.close();
                System.out.println("----------接続終了----------");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
	}
}
