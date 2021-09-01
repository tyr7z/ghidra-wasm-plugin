package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.StructureUtils;

public class WasmDataSegment implements StructConverter {

	private LEB128 index;
	private ConstantExpression offsetExpr;
	private long fileOffset;
	private LEB128 size;
	private byte[] data;

	public WasmDataSegment(BinaryReader reader) throws IOException {
		int mode = reader.readNextUnsignedByte();
		if (mode == 2) {
			index = LEB128.readUnsignedValue(reader);
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

		size = LEB128.readUnsignedValue(reader);
		fileOffset = reader.getPointerIndex();
		data = reader.readNextByteArray((int) size.asLong());
	}

	public long getIndex() {
		if (index == null)
			return 0;
		return index.asLong();
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public Long getMemoryOffset() {
		if (offsetExpr != null) {
			return offsetExpr.asI32();
		}
		return null;
	}

	public long getSize() {
		return size.asLong();
	}

	public byte[] getData() {
		return data;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		String structName = "data_segment_" + getIndex();
		if (getMemoryOffset() != null) {
			structName += "_" + getMemoryOffset();
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
