package yetmorecode.ghidrarest.ghidra;

import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.task.ConsoleTaskMonitor;

public class HeadlessRestConfiguration extends HeadlessGhidraApplicationConfiguration {

	public HeadlessRestConfiguration() {
		monitor = new ConsoleTaskMonitor();
	}
}
