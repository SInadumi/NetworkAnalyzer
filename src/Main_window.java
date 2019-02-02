
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.sql.SQLException;
import java.util.ArrayList;

import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

public class Main_window extends JFrame implements WindowListener {
	// グローバル変数の設定
	static private String[] columnNames = { "No.", "Time", "From", "To", "Protocol", "length", "Info" };

	static ArrayList<String[]> data = new ArrayList<String[]>();
	// static ArrayList<ArrayList<String>> data = new
	// ArrayList<ArrayList<String>>();
	static DefaultTableModel model = new DefaultTableModel(columnNames, 0);
	JPanel m = new JPanel();
	static JTable table = new JTable(model);
	JScrollPane sp = new JScrollPane(table);
	static JMenuBar Bar = new JMenuBar();
	JMenu[] CMenu = new JMenu[6];
	JMenuItem[][] Item = new JMenuItem[6][4];
	Action flow = new Action();
	Action stat = new Action();
	Action filter = new Action();
	static Action st = new Action();
	// アイコンの出典 http://icooon-mono.com
	String icon_sa = "icon/start.png";
	String icon_so = "icon/stopping.png";
	String icon_re = "icon/reload.png";
	String icon_qu = "icon/question.png";
	ImageIcon start_icon = new ImageIcon(this.getClass().getClassLoader().getResource(icon_sa));
	ImageIcon stop_icon = new ImageIcon(this.getClass().getClassLoader().getResource(icon_so));
	ImageIcon reload_icon = new ImageIcon(this.getClass().getClassLoader().getResource(icon_re));
	ImageIcon question = new ImageIcon(this.getClass().getClassLoader().getResource(icon_qu));

	static int id = 1;

	static int S_re = 0; // scroll start stop 判定
	static int reload = 0; // reload 判定

	// Filter変数の設定
	public static String pt[];
	public static String p;

	public static int flg = 0;
	public static int bflg = 0;
	 // static Con_DB db = new Con_DB();
	
	//パケット詳細を保持する変数
	static String p_exp; //ヘッダ部分
	static ArrayList<String> p_content=new ArrayList<String>();//パケット中身の16進数表示
	

	public static void main(String[] args) {
		try {
			
			Con_DB db=new Con_DB();
			db.Open();
			try {
				db.Sql_clear();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			db.Fin();
			// 初めのデバイス選択
			// db.Open();
			Device dev = new Device();
			dev.P_dev();
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			// db.Fin();
		}
	}

	static public void Reload_Func() {
		S_re = st.Stop_start();
		reload = st.Reload();
		if (S_re == 0) {
			int rowcount = model.getRowCount();
			table.scrollRectToVisible(table.getCellRect(rowcount, 0, true));
		}
		if (reload == 1) {
			data.clear();
			model.setRowCount(0);
			id = 1;
		}
		reload = st.Reload_2();// Action内のリロード変数を 0 に設定

	}

	static public void Packet_Detail(ArrayList<String> con,String ex) {
		p_content.addAll(con);
		p_exp=ex;
	}
	static public void Data_Initialize(String id_1, String date, String from, String to, String Protocol, String length,
			String info) {

		if (bflg == 0) {
			for (int n = 0; n < data.size(); n++) {
				String[] str = data.get(n);
				for (int i = 0; i < 7; i++) {
					if (pt[i].equals(str[4]) && Action.ad.equals("")) {
						model.addRow(data.get(n));

					} else if (pt[i].equals(str[4]) && ((Action.ad.equals(str[2])) || (Action.ad.equals(str[3])))) {
						model.addRow(data.get(n));

					} else if (pt[i].equals("0") && ((Action.ad.equals(str[2])) || (Action.ad.equals(str[3])))) {
						model.addRow(data.get(n));

					} else {
						break;
					}
				}

			}
			bflg = 1;
		}

		data.add(new String[] { id_1, date, from, to, Protocol, length, info });
		if (flg == 0) {
			model.addRow(data.get(Integer.valueOf(id_1) - 1));
			Reload_Func();

		} else if (flg == 1) {
			p = Packet.win[4];
			for (int i = 0; i < 15; i++) {
				if (pt[i].equals(p) && Action.ad.equals("")) {
					model.addRow(data.get(Integer.valueOf(id_1) - 1));
					Reload_Func();
				} else if (pt[i].equals(p)&& ((Action.ad.equals(Packet.win[2])) || (Action.ad.equals(Packet.win[3])))) {
					model.addRow(data.get(Integer.valueOf(id_1) - 1));
					Reload_Func();
				} else if (pt[i].equals("0")&& ((Action.ad.equals(Packet.win[2])) || (Action.ad.equals(Packet.win[3])))) {
					model.addRow(data.get(Integer.valueOf(id_1) - 1));
					Reload_Func();
				}
			}
		}
	}

	Main_window() {
		// JFrameの設定
		this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		this.setBounds(10, 10, 1200, 1000);
		this.setTitle("ネットワークアナライザ");
		this.setVisible(true);
		this.setResizable(false);
		this.setJMenuBar(Bar);
		this.addWindowListener(this);
		// テーブル定義
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		table.setAutoCreateRowSorter(true);
		table.setEnabled(false);
		TableColumn[] column = new TableColumn[7];
		// カラムの幅を設定
		DefaultTableColumnModel columnModel = (DefaultTableColumnModel) table.getColumnModel();
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			column[i] = columnModel.getColumn(i);
			if (i == 0 || i == 4 || i == 5) {
				column[i].setPreferredWidth(75);
			} else if (i == 1 || i == 2 || i == 3) {
				column[i].setPreferredWidth(200);
			} else
				column[i].setPreferredWidth(300);
		}
		// セルがダブルクリックされたか
		table.addMouseListener(new MouseAdapter() {
			public void mouseClicked(MouseEvent me) {
				String p_pcontent="1 ";
				String p_pexp="";
				
				if (me.getClickCount() == 2) {
					Point pt = me.getPoint();
					int idx = table.rowAtPoint(pt);
					if (idx >= 0) {
						int row = table.convertRowIndexToModel(idx);
						/*String str = String.format("%s (%s)", model.getValueAt(row, 0), model.getValueAt(row, 1),
								model.getValueAt(row, 2), model.getValueAt(row, 3), model.getValueAt(row, 4),
								model.getValueAt(row, 5), model.getValueAt(row, 6));*/
//						String hello = String.format("%s行目が選択されました", model.getValueAt(row, 0));
						int c_p=1;
						int c_c=1;
						for (String s : p_content) {
							p_pcontent=p_pcontent.concat(s.concat(s+" "));
							if((c_p%8)==0) {
								c_c++;
								p_pcontent=p_pcontent.concat("\n"+c_c+" ");
								
							}
							c_p++;
						}
						p_pexp=p_exp;
						p_pexp=p_pexp.replaceFirst("null","<html><body>");
						p_pexp=p_pexp.replace("\n","<br >");
						p_pexp=p_pexp.concat("</body></html>");
						System.out.println("---------------------------------------");
						System.out.println("CONTENTS\n"+p_pcontent);
						System.out.println("EXPs\n"+p_pexp);
						System.out.println("---------------------------------------");
						new PacketFlow(p_pexp,p_pcontent);
						p_pexp="";
						p_pcontent="";
						p_exp="";
						p_content.clear();
						
//						flow.Paint_flow();
						//JOptionPane.showMessageDialog(table, str, "title", JOptionPane.INFORMATION_MESSAGE);

					}
				}
			}
		});

		// カラム設定
		// ARP -> Red , TCP -> GREEN , DNS -> BLUE
		// switch (data.get()){

		// }

		// パネル設定
		// m.setLayout(new FlowLayout(FlowLayout.LEFT, -1, 0));
		m.setPreferredSize(new Dimension(1100, 950));
		m.add(sp);
		// m.add(Bar);
		// Container Pane = frame.getContentPane();
		// Pane.add(m, BorderLayout.PAGE_START);
		getContentPane().add(m, BorderLayout.PAGE_START);
		sp.setPreferredSize(new Dimension(1100, 950));
		sp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);

		// メニュー定義
		CMenu[0] = new JMenu("ツール");
		CMenu[1] = new JMenu("統計機能");
		CMenu[2] = new JMenu("ヘルプ");
		CMenu[3] = new JMenu();
		CMenu[4] = new JMenu();
		CMenu[5] = new JMenu();
		CMenu[2].setIcon(question);
		CMenu[3].setIcon(start_icon);
		CMenu[4].setIcon(stop_icon);
		CMenu[5].setIcon(reload_icon);

		Item[0][0] = new JMenuItem("フィルタ");
		Item[1][0] = new JMenuItem("IO Graph");
		Item[2][0] = new JMenuItem("ヘルプ");
		//Item[2][1] = new JMenuItem("使用方法");
		Item[3][0] = new JMenuItem("start");
		Item[3][1] = new JMenuItem("scroll_start");
		Item[4][0] = new JMenuItem("stop");
		Item[4][1] = new JMenuItem("scroll_stop");
		Item[5][0] = new JMenuItem("reload");

		Item[2][0].addActionListener(st);
		Item[3][0].addActionListener(st);
		Item[3][1].addActionListener(st);
		Item[4][0].addActionListener(st);
		Item[4][1].addActionListener(st);
		Item[5][0].addActionListener(st);

		Bar.add(CMenu[0]);
		Bar.add(CMenu[1]);
		Bar.add(CMenu[3]);
		Bar.add(CMenu[4]);
		Bar.add(CMenu[5]);
		Bar.add(Box.createHorizontalGlue());// ヘルプを右端に移動
		Bar.add(CMenu[2]);

		CMenu[0].add(Item[0][0]);
		CMenu[1].add(Item[1][0]);
		CMenu[2].add(Item[2][0]);
		//CMenu[2].add(Item[2][1]);
		CMenu[3].add(Item[3][0]);
		CMenu[3].add(Item[3][1]);
		CMenu[4].add(Item[4][0]);
		CMenu[4].add(Item[4][1]);
		CMenu[5].add(Item[5][0]);

		// ページ移動
		Item[0][0].addActionListener(filter);
		Item[1][0].addActionListener(stat);
	}

	public void windowClosed(WindowEvent e) {
		Run_Thread.end=true;
	}

	@Override
	public void windowActivated(WindowEvent arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void windowClosing(WindowEvent arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void windowDeactivated(WindowEvent arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void windowDeiconified(WindowEvent arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void windowIconified(WindowEvent arg0) {
		// TODO Auto-generated method stub

	}

	@Override
	public void windowOpened(WindowEvent arg0) {
		// TODO Auto-generated method stub

	}

}