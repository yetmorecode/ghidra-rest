package yetmorecode.ghidrarest.controller;

import java.io.IOException;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.framework.Application;
import ghidra.framework.ModuleInitializer;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.classfinder.ClassSearcher;

@RestController
public class ApplicationController {
	@GetMapping("/application")
	public String get() {
		var json = new JsonObject();
		json.addProperty("name", Application.getName());
		json.addProperty("buildDate", Application.getBuildDate());
		json.addProperty("release", Application.getApplicationReleaseName());
		json.addProperty("version", Application.getApplicationVersion());
		try {
			json.addProperty("applicationRoot", Application.getApplicationRootDirectory().getCanonicalPath());
			json.addProperty("userSettings", Application.getUserSettingsDirectory().getCanonicalPath());
			json.addProperty("userCache", Application.getUserCacheDirectory().getCanonicalPath());
			json.addProperty("userTemp", Application.getUserTempDirectory().getCanonicalPath());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		var modules = new JsonArray();
		List<ModuleInitializer> instances = ClassSearcher.getInstances(ModuleInitializer.class);
		for (ModuleInitializer initializer : instances) {
			var module = new JsonObject();
			module.addProperty("name", initializer.getName());
			module.addProperty("class", initializer.getClass().toString());
			modules.add(module);
		}
		json.add("modules", modules);
		var languages = new JsonArray();
		var service = DefaultLanguageService.getLanguageService();
		if (service != null) {
			for (var ld : service.getLanguageDescriptions(true)) {
				var language = new JsonObject();
				language.addProperty("id", ld.getLanguageID().toString());
				language.addProperty("description", ld.getDescription());
				language.addProperty("variant", ld.getVariant());
				language.addProperty("minor", ld.getMinorVersion());
				language.addProperty("version", ld.getVersion());
				language.addProperty("size", ld.getSize());
				language.addProperty("endian", ld.getEndian().toString());
				language.addProperty("deprecated", ld.isDeprecated());
				language.addProperty("instrcutionEndian", ld.getInstructionEndian().toString());
				language.addProperty("processorClass", ld.getProcessor().getClass().toString());
				
				var specs = new JsonArray();
				for (var c : ld.getCompatibleCompilerSpecDescriptions()) {
					var spec = new JsonObject();
					spec.addProperty("name", c.getCompilerSpecName());
					spec.addProperty("source", c.getSource());
					specs.add(spec);
				}
				language.add("compatibleCompilerSpecs", specs);
				languages.add(language);
			}
		}
		json.add("languages", languages);
		return json.toString();
	}
}