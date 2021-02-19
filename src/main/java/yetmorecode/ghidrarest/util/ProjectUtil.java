package yetmorecode.ghidrarest.util;

import ghidra.app.script.GhidraState;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class ProjectUtil {
	
	public static Program currentProgram;
	public static int transactionID = -1;
	
	/**
	 * Opens the specified program in the current tool.
	 *
	 * @param program the program to open
	 */
	public void openProgram(Program program) {
		/*
		PluginTool tool = state.getTool();
		if (tool == null) {
			return;
		}
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program);
		end(true);
		GhidraState newState = new GhidraState(tool, tool.getProject(), program, null, null, null);
		set(newState, monitor, writer);
		start();
		*/
	}
	
	/**
	 * Starts a transaction on the current program.
	 */
	public final void start() {
		if (currentProgram == null) {
			return;
		}
		if (transactionID == -1) {
			transactionID = currentProgram.startTransaction(getClass().getName());
		}
	}

	/**
	 * Ends the transactions on the current program.
	 * @param commit true if changes should be committed
	 */
	public final void end(boolean commit) {
		if (currentProgram == null) {
			return;
		}
		if (transactionID != -1) {
			currentProgram.endTransaction(transactionID, commit);
			transactionID = -1;
		}
	}
}
