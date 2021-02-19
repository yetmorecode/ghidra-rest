package yetmorecode.ghidrarest.util;

import java.io.File;

import ghidra.app.util.task.OpenProgramTask;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.NotFoundException;
import yetmorecode.ghidrarest.GhidraRestApplication;

public class GhidraUtils {

	public static Project currentProject;
	public static Program currentProgram;
	
	public static Project openProject(File projectFile) {
		try {
			return GhidraRestApplication.launch.projectManager.openProject(
				new ProjectLocator(projectFile.getParent(), projectFile.getName().substring(0, projectFile.getName().length() - 4)), 
				false, 
				false
			);
		} catch (NotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotOwnerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (LockException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public static Program openProgram(DomainFile file, Object consumer) {
		long start = System.currentTimeMillis();
		OpenProgramTask task = new OpenProgramTask(file, true, consumer);
		task.run(null);
		var openProgram = task.getOpenProgram();
		long finish = System.currentTimeMillis();
		long timeElapsed = finish - start;
		System.out.println("Opened program (" + timeElapsed + "ms): " + openProgram.getName() + " " + openProgram.getFunctionManager().getFunctionCount());
		return openProgram;
	}
	
}
