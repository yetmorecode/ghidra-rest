package yetmorecode.ghidrarest.controller;

import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.data.DataType;
import yetmorecode.ghidrarest.util.GhidraUtils;

@RestController
public class DatatypeController {
	@GetMapping(value = "/datatypes", produces = { "application/json" })
	public String getAll(HttpServletRequest request) {
		var json = new JsonArray();
		
		if (GhidraUtils.currentProgram != null) {
			ArrayList<DataType> list = new ArrayList<>();
			GhidraUtils.currentProgram.getDataTypeManager().getAllDataTypes(list);
			for (DataType datatype : list) {
				var d = new JsonObject();
				d.addProperty("name", datatype.getName());
				d.addProperty("category", datatype.getCategoryPath().toString());
				d.addProperty("lastChanged", datatype.getLastChangeTime());
				d.addProperty("length", datatype.getLength());
				json.add(d);
				
			}
		}
		return json.toString();
	}
}