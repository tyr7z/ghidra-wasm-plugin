package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;
import wasm.format.WasmEnums.ValType;

public class WasmElementSegment implements StructConverter {

	private int flags;
	private ElementSegmentMode mode;

	private Leb128 tableidx; 				/* if (flags & 3) == 2 */
	private ConstantExpression offset; 		/* if (flags & 1) == 0 */
	private Leb128 count;

	int elemkind; 							/* if (flags & 4) == 0 */
	private List<Leb128> funcidxs; 			/* if (flags & 4) == 0 */

	ValType elemtype; 						/* if (flags & 4) != 0 */
	private List<ConstantExpression> exprs; /* if (flags & 4) != 0 */

	public enum ElementSegmentMode {
		active,
		passive,
		declarative,
	}

	public WasmElementSegment(BinaryReader reader) throws IOException {
		flags = reader.readNextUnsignedByte();
		if ((flags & 3) == 2) {
			/* active segment with explicit table index */
			tableidx = new Leb128(reader);
		} else {
			/* tableidx defaults to 0 */
			tableidx = null;
		}

		if ((flags & 1) == 0) {
			/* active segment */
			mode = ElementSegmentMode.active;
			offset = new ConstantExpression(reader);
		} else if ((flags & 2) == 0) {
			mode = ElementSegmentMode.passive;
		} else {
			mode = ElementSegmentMode.declarative;
		}

		if ((flags & 3) == 0) {
			/* implicit element type */
			elemkind = 0;
			elemtype = ValType.funcref;
		} else {
			/* explicit element type */
			int typeCode = reader.readNextUnsignedByte();
			if ((flags & 4) == 0) {
				/* elemkind */
				elemkind = typeCode;
			} else {
				/* reftype */
				elemtype = ValType.fromByte(typeCode);
			}
		}

		count = new Leb128(reader);
		if ((flags & 4) == 0) {
			/* vector of funcidx */
			funcidxs = new ArrayList<>();
			for (int i = 0; i < count.getValue(); i++) {
				funcidxs.add(new Leb128(reader));
			}
		} else {
			/* vector of expr */
			exprs = new ArrayList<>();
			for (int i = 0; i < count.getValue(); i++) {
				exprs.add(new ConstantExpression(reader));
			}
		}
	}

	public ElementSegmentMode getMode() {
		return mode;
	}

	public long getTableIndex() {
		if (tableidx == null) {
			return 0;
		}
		return tableidx.getValue();
	}

	public long getOffset() {
		if (offset == null) {
			return -1;
		}

		Long result = offset.getValueI32();
		if (result == null) {
			return -1;
		}
		return result;
	}

	public ValType getElementType() {
		if ((flags & 4) == 0) {
			if (elemkind == 0) {
				return ValType.funcref;
			}
			return null;
		} else {
			return elemtype;
		}
	}

	public byte[] getInitData() {
		int count = (int) this.count.getValue();
		byte[] result = new byte[count * 8];
		Arrays.fill(result, (byte) 0xff);

		if (funcidxs != null) {
			for (int i = 0; i < count; i++) {
				byte[] v = ConstantExpression.longToBytes(funcidxs.get(i).getValue());
				System.arraycopy(v, 0, result, i * 8, 8);
			}
			return result;
		}

		if (exprs != null) {
			for (int i = 0; i < count; i++) {
				byte[] v = exprs.get(i).getInitBytes();
				if (v != null)
					System.arraycopy(v, 0, result, i * 8, 8);
			}
			return result;
		}
		return null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("element_segment");
		StructureUtils.addField(structure, BYTE, "flags");
		if (tableidx != null) {
			StructureUtils.addField(structure, tableidx, "tableidx");
		}
		if (offset != null) {
			StructureUtils.addField(structure, offset, "offset");
		}
		if ((flags & 3) != 0) {
			/* both elemkind and reftype are single bytes */
			StructureUtils.addField(structure, BYTE, "element_type");
		}

		StructureUtils.addField(structure, count, "count");
		if (funcidxs != null) {
			for (int i = 0; i < funcidxs.size(); i++) {
				StructureUtils.addField(structure, funcidxs.get(i), "element" + i);
			}
		}
		if (exprs != null) {
			for (int i = 0; i < exprs.size(); i++) {
				StructureUtils.addField(structure, exprs.get(i), "element" + i);
			}
		}

		return structure;
	}
}
