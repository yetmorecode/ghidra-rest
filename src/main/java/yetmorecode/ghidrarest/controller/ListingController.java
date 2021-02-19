package yetmorecode.ghidrarest.controller;

import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.GenericAddress;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.DefinedDataIterator;
import yetmorecode.ghidrarest.util.GhidraUtils;

@RestController
public class ListingController {
	@GetMapping(value = "/listing/{address}", produces = { "application/json" })
	public String getAll(HttpServletRequest request, @PathVariable("address") String address) {
		var json = new JsonArray();
		
		long a = Long.parseLong(address, 10);
		
		if (GhidraUtils.currentProgram != null) {
			var program = GhidraUtils.currentProgram;
			var listing = program.getListing();
			
			var space = program.getAddressFactory().getDefaultAddressSpace();
			var set = new AddressSet(space.getAddress(a), space.getAddress(a+20));
			for (var data : listing.getCodeUnits(set, true)) {
				var j = new JsonObject();
				j.addProperty("address", data.getAddress().getOffset());
				j.addProperty("mnemonic", data.getMnemonicString());
				j.addProperty("label", data.getLabel());
				j.addProperty("length", data.getLength());
				j.addProperty("numOperands", data.getNumOperands());
				
				var props = new JsonArray();
				var iter = data.propertyNames();
				while (iter.hasNext()) {
					var propName = iter.next();
					var prop = new JsonObject();
					prop.addProperty("name", propName);
					prop.addProperty("value", data.getStringProperty(propName));
				}
				j.add("properties", props);
				
				var operands = new JsonArray();
				for (int i = 0; i < data.getNumOperands(); i++) {
					var operand = new JsonObject();
					operand.addProperty("number", i);
					if (data instanceof Instruction) {
						var reg = ((Instruction) data).getRegister(i);
						var addr = data.getAddress(i);
						var scalar = data.getScalar(i);
						var representation = ((Instruction) data).getDefaultOperandRepresentation(i);
						
						operand.addProperty("register", reg != null ? reg.getName() : null);
						operand.addProperty("address", addr != null ? addr.toString() : null);
						operand.addProperty("scalar", scalar != null ? scalar.toString() : null);
						operand.addProperty("representation", representation);
					}
					
					
					var references = new JsonArray();
					for (var ref : data.getOperandReferences(i)) {
						var reference = new JsonObject();
						reference.addProperty("isRegister", ref.isRegisterReference());
						reference.addProperty("isMemory", ref.isMemoryReference());
						reference.addProperty("isOffset", ref.isOffsetReference());
						reference.addProperty("isOperand", ref.isOperandReference());
						references.add(reference);
					}
					operand.add("references", references);
					operands.add(operand);
				}
				j.add("operands", operands);
				
				json.add(j);	
			}
		}
		return json.toString();
	}
}
