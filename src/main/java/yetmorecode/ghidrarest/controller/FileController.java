package yetmorecode.ghidrarest.controller;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import yetmorecode.ghidrarest.util.GhidraUtils;

@RestController
public class FileController {
	@GetMapping(value = "/files", produces = { "application/json" })
	public String getAll(HttpServletRequest request) {
		var files = new JsonArray();
		var p = GhidraUtils.currentProject;
		if (p != null) {
			try {
				addFiles(request, files, p.getProjectData().getRootFolder());
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return files.toString();
	}
	
	@GetMapping(value = "/files/{name}", produces = { "application/json" })
	public String get(HttpServletRequest request, @PathVariable("name") String name) throws IOException {
		var p = GhidraUtils.currentProject;
		
		if (p != null) {
			System.out.println("showing " + name);
			var file = p.getProjectData().getFileByID(name);
			return renderFile(file).toString();	
		}
		
		return "{}";
	}
	
	@GetMapping(value = "/files/{name}/open", produces = { "application/json" })
	public String openFile(HttpServletRequest request, @PathVariable("name") String name) throws IOException {
		var p = GhidraUtils.currentProject;
		
		if (p != null) {
			if (GhidraUtils.currentProgram != null) {
				GhidraUtils.currentProgram.release(this);
			}
			
			var file = p.getProjectData().getFileByID(name);
			GhidraUtils.currentProgram = GhidraUtils.openProgram(file, this);
		}
		
		return getAll(request);
	}
	
	
	
	private void addFiles(HttpServletRequest request, JsonArray files, DomainFolder folder) throws IOException {
		for (var f : folder.getFiles()) {
			files.add(renderFile(f));
		}
		for (var f : folder.getFolders()) {
			addFiles(request, files, f);
		}
	}
	
	private JsonObject renderFile(DomainFile f) throws IOException {
		var json = new JsonObject();
		json.addProperty("name", f.getName());
		json.addProperty("contentType", f.getContentType());
		json.addProperty("fileId", f.getFileID());
		json.addProperty("open", GhidraUtils.currentProgram != null && GhidraUtils.currentProgram.getDomainFile().getFileID() == f.getFileID());
		json.addProperty("pathname", f.getPathname());
		json.addProperty("lastModified", f.getLastModifiedTime());
		json.addProperty("lastestVersion", f.getLatestVersion());
		json.addProperty("version", f.getVersion());
		
		final String baseUrl = 
				ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
		
		json.addProperty("link", baseUrl + "/files/" + URLEncoder.encode(f.getName(), Charset.defaultCharset()));
		var versions = new JsonArray();
		if (f.getVersionHistory() != null) {
			for (var r : f.getVersionHistory()) {
				var v = new JsonObject();
				v.addProperty("version", r.getVersion());
				v.addProperty("comment", r.getComment());
				v.addProperty("user", r.getUser());
				v.addProperty("creationTime", r.getCreateTime());
			}	
		}
		json.add("versions", versions);
		var meta = new JsonObject();
		for (Map.Entry<String, String> e : f.getMetadata().entrySet()) {
			meta.addProperty(e.getKey(), e.getValue());
		}
		json.add("meta", meta);
		return json;
	}
}
