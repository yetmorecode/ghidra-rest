package yetmorecode.ghidrarest.controller;

import java.io.File;
import java.util.ArrayList;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.FileUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import yetmorecode.ghidrarest.util.GhidraUtils;

@RestController
public class ProjectController {
	
	public ProjectController() {
		
		long start = System.currentTimeMillis();
		projectFiles = findProjectFiles();
		long finish = System.currentTimeMillis();
		long timeElapsed = finish - start;
		System.out.println("ProjectController: project file lookup took " + timeElapsed + "ms");
		
	}
	
	private ArrayList<File> projectFiles = new ArrayList<>();
	
	@GetMapping(value = "/projects", produces = { "application/json" })
	public String getProjects(HttpServletRequest request) {
		var projects = new JsonArray();
		var project = GhidraUtils.currentProject;
		for (var projectFile : projectFiles) {
			var p = new JsonObject();
			var name = projectFile.getName().substring(0, projectFile.getName().length() - 4);
			var path = projectFile.getParent();
			p.addProperty("name", name);
			p.addProperty("filename", name + ".gpr");
			p.addProperty("path", path);
			p.addProperty("pathname", path + "\\" + name + ".gpr");
			p.addProperty("open", project != null && project.getName().equals(name));
			p.addProperty("locked", new File(path + "\\" + name + ".lock").exists() || new File(path + "\\" + name + ".lock~").exists());
			projects.add(p);	
		}
		return projects.toString();
	}
	
	@GetMapping(value = "/projects/open/{name}", produces = { "application/json" })
	public String openProject(HttpServletRequest request, @PathVariable("name") String name) {
		var project = GhidraUtils.currentProject;
		if (project != null) {
			if (project.getName().equals(name)) {
				// project is already open
				return getProjects(request);
			} else {
				// close old project
				project.close();
				GhidraUtils.currentProject = null;
			}
		}
		for (var projectFile : projectFiles) {
			if (projectFile.getName().equals(name + ".gpr")) {
				GhidraUtils.currentProject = GhidraUtils.openProject(projectFile);
			}
		}
		return getProjects(request);
	}
	
	@GetMapping(value = "/projects/close", produces = { "application/json" })
	public String closeProject(HttpServletRequest request) {
		var project = GhidraUtils.currentProject;
		if (project != null) {
			project.close();
		}
		GhidraUtils.currentProject = null;
		return getProjects(request);
	}
	
	private ArrayList<File> findProjectFiles() {
		String directories[] = new String[] {
			"D:\\Games",
			"D:\\eclipse-ghidra-workspace"
		};
		var files = new ArrayList<File>();
		for (var d : directories) {
			var directoryFiles = FileUtils.listFiles(new File(d), new String[] {"gpr"}, true);
			for (var df : directoryFiles) {
				files.add(df);
			}
		}
		return files;
	}
}
