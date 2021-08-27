package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer64DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;
import wasm.format.WasmEnums.ValType;

public class WasmTableType implements StructConverter {

	private ValType elemType;
	private WasmResizableLimits limits;

	public WasmTableType(BinaryReader reader) throws IOException {
		elemType = ValType.fromByte(reader.readNextUnsignedByte());
		limits = new WasmResizableLimits(reader);
	}

	public DataType getElementDataType() {
		switch (elemType) {
		case funcref:
		case externref:
			return Pointer64DataType.dataType;
		default:
			return null;
		}
	}

	public WasmResizableLimits getLimits() {
		return limits;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("table_type");
		StructureUtils.addField(structure, BYTE, "element_type");
		StructureUtils.addField(structure, limits, "limits");
		return structure;
	}
}
