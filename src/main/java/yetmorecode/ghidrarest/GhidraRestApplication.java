package yetmorecode.ghidrarest;

import javax.annotation.PreDestroy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import yetmorecode.ghidrarest.ghidra.HeadlessRestRun;
import yetmorecode.ghidrarest.ghidra.Launcher;
import yetmorecode.ghidrarest.util.GhidraUtils;


@SpringBootApplication
public class GhidraRestApplication {

	public static HeadlessRestRun launch;
	
	public static void main(String[] args) {
		try {
			// Launch a headless ghidra instance
			launch = (HeadlessRestRun) Launcher.main(new String[] {"yetmorecode.ghidrarest.ghidra.HeadlessRestRun"});
			
			// Launch the REST server
			SpringApplication.run(GhidraRestApplication.class, args);
		} catch (Exception e) {
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
			System.out.println("failed:");
			e.printStackTrace();
		}
	}
}
