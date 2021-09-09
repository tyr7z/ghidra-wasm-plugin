package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureBuilder;
import wasm.format.WasmEnums.ValType;

public class WasmTableType implements StructConverter {

	private ValType elemType;
	private WasmResizableLimits limits;

	public WasmTableType(BinaryReader reader) throws IOException {
		elemType = ValType.fromByte(reader.readNextUnsignedByte());
		limits = new WasmResizableLimits(reader);
	}

	public ValType getElementType() {
		return elemType;
	}

	public DataType getElementDataType() {
		return elemType.asDataType();
	}

	public WasmResizableLimits getLimits() {
		return limits;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureBuilder builder = new StructureBuilder("table_type");
		builder.add(BYTE, "element_type");
		builder.add(limits, "limits");
		return builder.toStructure();
	}
}
