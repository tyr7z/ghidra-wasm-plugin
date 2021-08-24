package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;
import wasm.format.sections.structures.ConstantExpression.ConstantInstruction;

public class WasmDataSegment implements StructConverter {

	private Leb128 index;
	private ConstantExpression offsetExpr;
	private long fileOffset;
	private Leb128 size;
	private byte[] data;

	public WasmDataSegment(BinaryReader reader) throws IOException {
		byte mode = reader.readNextByte();
		if (mode == 2) {
			index = new Leb128(reader);
		} else {
			/* for mode < 2, index defaults to 0 */
			index = null;
		}

		if (mode == 0 || mode == 2) {
			/* "active" segment with predefined offset */
			offsetExpr = new ConstantExpression(reader);
		} else {
			/* "passive" segment loaded dynamically at runtime */
			offsetExpr = null;
		}

		size = new Leb128(reader);
		fileOffset = reader.getPointerIndex();
		data = reader.readNextByteArray((int) size.getValue());
	}

	public long getIndex() {
		if (index == null)
			return 0;
		return index.getValue();
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public long getOffset() {
		if (offsetExpr != null && offsetExpr.getInstructionType() == ConstantInstruction.I32_CONST) {
			return ((Leb128) offsetExpr.getRawValue()).getValue();
		}
		return -1;
	}

	public long getSize() {
		return size.getValue();
	}

	public byte[] getData() {
		return data;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String structName = "data_segment_" + getIndex();
		if (getOffset() != -1) {
			structName += "_" + getOffset();
		}
		Structure structure = StructureUtils.createStructure(structName);

		StructureUtils.addField(structure, BYTE, "mode");
		if (index != null) {
			StructureUtils.addField(structure, index, "index");
		}
		if (offsetExpr != null) {
			StructureUtils.addField(structure, offsetExpr, "offset");
		}
		StructureUtils.addField(structure, size, "size");
		if (data.length != 0) {
			StructureUtils.addArrayField(structure, BYTE, data.length, "data");
		}
		return structure;
	}
}
