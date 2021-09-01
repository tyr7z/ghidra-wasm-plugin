package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmFunctionBody implements StructConverter {

	private LEB128 bodySize;
	private List<WasmLocalEntry> locals = new ArrayList<WasmLocalEntry>();
	private LEB128 localCount;
	private long instructionsOffset;
	private byte[] instructions;

	public WasmFunctionBody(BinaryReader reader) throws IOException {
		bodySize = LEB128.readUnsignedValue(reader);
		int bodyStartOffset = (int) reader.getPointerIndex();
		localCount = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < localCount.asLong(); ++i) {
			locals.add(new WasmLocalEntry(reader));
		}
		instructionsOffset = reader.getPointerIndex();
		instructions = reader.readNextByteArray((int) (bodyStartOffset + bodySize.asLong() - instructionsOffset));
	}

	public long getOffset() {
		return instructionsOffset;
	}

	public byte[] getInstructions() {
		return instructions;
	}

	public byte[] getLocals() {
		int localCount = 0;
		for (WasmLocalEntry local : locals) {
			localCount += local.getCount();
		}
		byte[] result = new byte[localCount];
		int pos = 0;
		for (WasmLocalEntry local : locals) {
			Arrays.fill(result, pos, pos + local.getCount(), (byte) local.getType());
			pos += local.getCount();
		}
		return result;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("function_body_" + instructionsOffset);
		StructureUtils.addField(structure, bodySize, "body_size");
		StructureUtils.addField(structure, localCount, "local_count");
		for (int i = 0; i < localCount.asLong(); i++) {
			StructureUtils.addField(structure, locals.get(i).toDataType(), "compressed_locals_" + i);
		}
		StructureUtils.addArrayField(structure, BYTE, instructions.length, "instructions");
		return structure;
	}
}
