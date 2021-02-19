package yetmorecode.ghidrarest.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import yetmorecode.ghidrarest.util.GhidraUtils;

@RestController
public class FunctionController {
	@GetMapping(value = "/functions", produces = { "application/json" })
	public String getAll(HttpServletRequest request) {
		var json = new JsonArray();
		
		if (GhidraUtils.currentProgram != null) {
			for (var function : GhidraUtils.currentProgram.getFunctionManager().getFunctions(true)) {
				var f = new JsonObject();
				f.addProperty("name", function.getName());
				f.addProperty("parameterCount", function.getParameterCount());
				f.addProperty("address", function.getEntryPoint().getOffset());
				f.addProperty("comment", function.getComment());
				json.add(f);
			}
		}
		return json.toString();
	}
}
