package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;

public class WasmFuncType implements StructConverter {

	@SuppressWarnings("unused")
	private int form; /* always 0 in this version */
	private Leb128 paramCount;
	private byte[] paramTypes;
	private Leb128 returnCount;
	private byte[] returnTypes;

	public WasmFuncType(BinaryReader reader) throws IOException {
		form = reader.readNextUnsignedByte();
		paramCount = new Leb128(reader);
		paramTypes = reader.readNextByteArray((int) paramCount.getValue());
		returnCount = new Leb128(reader);
		returnTypes = reader.readNextByteArray((int) returnCount.getValue());
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
		Structure structure = StructureUtils.createStructure("func_type_" + paramCount.getValue() + "_" + returnCount.getValue());
		StructureUtils.addField(structure, BYTE, "form");
		StructureUtils.addField(structure, paramCount, "param_count");
		StructureUtils.addArrayField(structure, BYTE, (int) paramCount.getValue(), "param_types");
		StructureUtils.addField(structure, returnCount, "return_count");
		StructureUtils.addArrayField(structure, BYTE, (int) returnCount.getValue(), "return_types");
		return structure;
	}
}
