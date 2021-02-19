package yetmorecode.ghidrarest;

import javax.annotation.PreDestroy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import ghidra.framework.plugintool.util.PluginClassManager;
import yetmorecode.ghidrarest.ghidra.HeadlessRestRun;
import yetmorecode.ghidrarest.ghidra.Launcher;
import yetmorecode.ghidrarest.util.GhidraUtils;


@SpringBootApplication
public class GhidraRestApplication {

	public static HeadlessRestRun launch;
	
	
	public static void main(String[] args) {
		try {
			System.out.println("ClassLoader in use: " + ClassLoader.getSystemClassLoader().getClass().toString());
			launch = (HeadlessRestRun) Launcher.main(new String[] {"yetmorecode.ghidrarest.ghidra.HeadlessRestRun"});
			SpringApplication.run(GhidraRestApplication.class, args);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@PreDestroy
	public void onExit() {
		System.out.println("Shutting down Ghidra.. ");
		try {
			
			if (GhidraUtils.currentProgram != null) {
				System.out.println("Program still open: " + GhidraUtils.currentProgram.getName() + ".");
			}
			if (GhidraUtils.currentProject != null) {
				System.out.println("Project still open: " + GhidraUtils.currentProject.getName() + ". Closing..");
				GhidraUtils.currentProject.close();
			}
			
			launch.mainThread.join();
			System.out.println("success");
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			System.out.println("failed:");
			e.printStackTrace();
		}
	}
}
