package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;
import wasm.format.sections.structures.WasmFunctionBody;

public class WasmCodeSection extends WasmSection {

	private Leb128 count;
	private List<WasmFunctionBody> functions = new ArrayList<WasmFunctionBody>();

	public WasmCodeSection(BinaryReader reader) throws IOException {
		super(reader);
		count = new Leb128(reader);
		for (int i = 0; i < count.getValue(); ++i) {
			functions.add(new WasmFunctionBody(reader));
		}
	}

	public List<WasmFunctionBody> getFunctions() {
		return Collections.unmodifiableList(functions);
	}

	@Override
	protected void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		StructureUtils.addField(structure, count, "count");
		for (int i = 0; i < functions.size(); i++) {
			StructureUtils.addField(structure, functions.get(i), "function_" + i);
		}
	}

	@Override
	public String getName() {
		return ".code";
	}
}
