package yetmorecode.ghidrarest.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.framework.plugintool.util.PluginDescription;
import yetmorecode.ghidrarest.GhidraRestApplication;

@RestController
public class PluginController {
	@GetMapping("/plugins")
	public String getAll() {
		var plugins = new JsonArray();
		for (PluginDescription d : GhidraRestApplication.launch.pluginClassManager.getAllPluginDescriptions()) {
			var json = new JsonObject();
			json.addProperty("name", d.getName());
			json.addProperty("shortDescription", d.getShortDescription());
			json.addProperty("category", d.getCategory());
			json.addProperty("package", d.getPluginPackage().getName());
			json.addProperty("status", d.getStatus().toString());
			json.addProperty("description", d.getDescription());
			json.addProperty("moduleName", d.getModuleName());
			json.addProperty("sourceLocation", d.getSourceLocation());
			json.addProperty("class", d.getClass().toString());
			json.addProperty("pluginClass", d.getPluginClass().toString());
			plugins.add(json);
		}
		return plugins.toString();
	}
}
