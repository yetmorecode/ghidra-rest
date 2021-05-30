package yetmorecode.ghidrarest.ghidra;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.GhidraThreadGroup;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.util.PluginClassManager;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.remote.InetNameLookup;
import ghidra.util.SystemUtilities;

public class HeadlessRestRun implements GhidraLaunchable {

	private Logger log; // intentionally load later, after initialization
	public ProjectLocator projectLocator;
	public ProjectManager projectManager;
	public Project project;
	public PluginClassManager pluginClassManager;
	
	
	public Thread mainThread;
	
	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		
		Runnable mainTask = () -> {
			System.out.println("Hello Ghidra run");
			//System.out.println("ClassLoader in use: " + ClassLoader.getSystemClassLoader().getClass().toString());
			
			ApplicationConfiguration configuration = new HeadlessRestConfiguration();
				
			//configuration.setTaskMonitor(new StatusReportingTaskMonitor());
			Application.initializeApplication(layout, configuration);
	
			log = LogManager.getLogger(HeadlessRestRun.class);
			log.info("User " + SystemUtilities.getUserName() + " started Ghidra.");
	
			//initializeTooltips();
			//updateSplashScreenStatusMessage("Populating Ghidra help...");
			//GhidraHelpService.install();
			//ExtensionUtils.cleanupUninstalledExtensions();
			// Allows handling of old content which did not have a content type property
			//DomainObjectAdapter.setDefaultContentClass(ProgramDB.class);
	
			String projectPath = processArguments(args);
			System.out.println("GHIDRA open project: " + projectPath);
			
			projectManager = new GhidraProjectManager();
			pluginClassManager = new PluginClassManager(Plugin.class, FrontEndOnly.class);
			System.out.println("Added pluginClassManager");
			
			
		};

		// Automatically disable reverse name lookup if failure occurs
		InetNameLookup.setDisableOnFailure(true);

		// Start main thread in GhidraThreadGroup
		mainThread = new Thread(new GhidraThreadGroup(), mainTask, "Ghidra");
		mainThread.start();	
	}
	
	private String processArguments(String[] args) {
		//TODO remove this special handling when possible 
		if (args.length == 1 && (args[0].startsWith("-D") || args[0].indexOf(" -D") >= 0)) {
			args = args[0].split(" ");
		}
		String projectPath = null;
		for (String arg : args) {
			if (arg.startsWith("-D")) {
				String[] split = arg.substring(2).split("=");
				if (split.length == 2) {
					System.setProperty(split[0], split[1]);
				}
			}
			else {
				projectPath = arg;
			}
		}
		return projectPath;
	}
	
	private class GhidraProjectManager extends DefaultProjectManager {
		
	}

}
