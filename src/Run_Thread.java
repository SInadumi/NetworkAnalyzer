
public class Run_Thread extends Thread {
	static boolean end = false; 
	static boolean stop = true;
	

	public void run() {
		Main_window main = new Main_window();
		while (!(end)) {
			try {
				/*synchronized(this) {
					if (stop) wait();  
				}*/
				//if(!stop) {
					Create.analyze();
				//}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
	}

	/*public void startRun() {
		stop = false;
	}

	public void stopRun() {
		stop = true;
	}*/
	/*public void startRun() {
		this.notify();
	}
	public void StopRun() {
		System.out.println("-----------------------------------"+"\nstoprunが押されました");
		try {
			wait();
		} catch (InterruptedException e) {
			// TODO 自動生成された catch ブロック
			e.printStackTrace();
		}
		System.out.println(end+"\n"+"----------------------------------------");
	}*/

	public synchronized void setStop() {
		stop = !stop;
		System.out.println("-----------------------------------"+"\n"+stop);
		/*if (!stop) {
			notify();
		}*/
	}

}
