package yetmorecode.ghidrarest.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.Data;
import ghidra.program.util.DefinedDataIterator;
import yetmorecode.ghidrarest.util.GhidraUtils;

@RestController
public class StringController {
	@GetMapping(value = "/strings", produces = { "application/json" })
	public String getAll(HttpServletRequest request) {
		var json = new JsonArray();
		
		if (GhidraUtils.currentProgram != null) {
			for (Data stringInstance : DefinedDataIterator.definedStrings(GhidraUtils.currentProgram)) {
				var j = new JsonObject();
				j.addProperty("name", stringInstance.getAddressString(true, true));
				j.addProperty("address", stringInstance.getAddress().toString());
				j.addProperty("value", stringInstance.getDefaultValueRepresentation());
				json.add(j);
			}
		}
		return json.toString();
	}
}
