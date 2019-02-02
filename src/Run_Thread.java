public class Run_Thread extends Thread {
	static boolean end = false; 
	static boolean stop = true;
	

	public void run() {
		Main_window main = new Main_window();
		while (!(end)) {
			try {
					Create.analyze();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public synchronized void setStop() {
		stop = !stop;
		System.out.println("-----------------------------------"+"\n"+stop);
	}

}
