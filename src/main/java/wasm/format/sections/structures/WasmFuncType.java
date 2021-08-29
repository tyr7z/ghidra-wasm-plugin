package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmFuncType implements StructConverter {

	@SuppressWarnings("unused")
	private int form; /* always 0 in this version */
	private LEB128 paramCount;
	private byte[] paramTypes;
	private LEB128 returnCount;
	private byte[] returnTypes;

	public WasmFuncType(BinaryReader reader) throws IOException {
		form = reader.readNextUnsignedByte();
		paramCount = LEB128.readUnsignedValue(reader);
		paramTypes = reader.readNextByteArray((int) paramCount.asLong());
		returnCount = LEB128.readUnsignedValue(reader);
		returnTypes = reader.readNextByteArray((int) returnCount.asLong());
	}

	public byte[] getParamTypes() {
		return paramTypes;
	}

	public byte[] getReturnTypes() {
		return returnTypes;
	}

	@Override
	public String toString() {
		return paramTypes.length + "T -> " + returnTypes.length + "T";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("func_type_" + paramCount.asLong() + "_" + returnCount.asLong());
		StructureUtils.addField(structure, BYTE, "form");
		StructureUtils.addField(structure, paramCount, "param_count");
		StructureUtils.addArrayField(structure, BYTE, (int) paramCount.asLong(), "param_types");
		StructureUtils.addField(structure, returnCount, "return_count");
		StructureUtils.addArrayField(structure, BYTE, (int) returnCount.asLong(), "return_types");
		return structure;
	}
}
