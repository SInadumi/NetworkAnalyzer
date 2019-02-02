
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
public class Action extends JFrame implements ActionListener {
	int s_t=0;
	int re=0;
	public static String ad;
	public int Stop_start() {
		return s_t;
	}
	public int Reload() {
		return re;
	}
	public int Reload_2(){
		re=0;
		return re;
	}
	public void actionPerformed(ActionEvent e) {
		String str=e.getActionCommand();
		
		if(str =="IO Graph") {
			Statistics stat =new Statistics();
			try {
				stat.run();
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
		else if(str=="フィルタ") {
			Filter fil=new Filter();
			fil.P_fil();
		}
		else if(str=="stop"||str=="scroll_stop") {
			if(str=="scroll_stop"){
				s_t=1;
			}
			else if(str=="stop") {
				Run_Thread th = new Run_Thread();
				
				try {
					th.setStop();
				//wait();
				}catch(Exception ex) {
					ex.printStackTrace();
				}
			}
		}
		else if(str=="start"||str=="scroll_start") {
			if(str=="scroll_start"){
				s_t=0;
			}
			else if(str=="start") {
				try {
					Run_Thread th =new Run_Thread();
					//th.start();
					th.setStop();
				}catch(Exception ex) {
					ex.printStackTrace();
				}
			}
		}
		else if(str == "capture start") {
			Run_Thread th =new Run_Thread();
			System.out.println(th.stop);
			th.start();
			th.setStop();
		}
		else if(str == "ヘルプ") {
			UserHelp hh=new UserHelp();
			hh.Paint_UserHelp();
		}
		else if(str=="reload"){
			re=1;
			//統計変数のリセット
			Create.p_count=0;
			Create.start = System.currentTimeMillis();
			Create.cu_time = System.currentTimeMillis();
			Create.per_count=0;
			System.out.println(Create.per_count);
			Statistics st=new Statistics();
			st.DataClear();
		}
		else if(str=="適用") {
			Main_window.bflg=0;
			Main_window.model.setRowCount(0);
			Main_window.flg=1;
			ad=Filter.inputADR1.getText();
			Filter.plb=new int[15];
			Main_window.pt=new String[15];
			for(int i=0;i<15;i++) {
				if(Filter.ckbox[i].isSelected()) {
					Filter.plb[i]=1;
				}
				else {
					Filter.plb[i]=0;
				}
				if(Filter.plb[i]==1) {
					Main_window.pt[i]=Filter.ckbox[i].getText();
				}
				else {
					Main_window.pt[i]="0";
				}
			}
		}
		else if(str=="一括取消") {
			for(int i=0;i<15;i++) {
					Filter.ckbox[i].setSelected(false);
					}
		}
		else if(str=="全選択") {
			for(int i=0;i<15;i++) {
					Filter.ckbox[i].setSelected(true);
					}
		}
	}
}
