package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Float4DataType;
import ghidra.program.model.data.Float8DataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.StructureUtils;

/* A reader for expressions containing a single constant instruction.

In principle, constant expressions could contain more than one 

Such expressions consist of an instruction from the following list:
- t.const c
- ref.null
- ref.func x
- global.get x
followed by an explicit end byte (0x0b).
*/
public final class ConstantExpression implements StructConverter {

	private ConstantInstruction type;
	private Object value;

	public enum ConstantInstruction {
		I32_CONST, /* i32.const n: value is Leb128 */
		I64_CONST, /* i64.const n: value is Leb128 */
		F32_CONST, /* f32.const z: value is byte[4] */
		F64_CONST, /* f64.const z: value is byte[8] */
		REF_NULL_FUNCREF, /* ref.null funcref: value is null */
		REF_NULL_EXTERNREF, /* ref.null externref: value is null */
		REF_FUNC, /* ref.func x: value is Leb128 funcidx */
		GLOBAL_GET, /* global.get x: value is Leb128 globalidx */
	}

	public ConstantExpression(BinaryReader reader) throws IOException, IllegalArgumentException {
		int typeCode = reader.readNextUnsignedByte();

		switch (typeCode) {
		case 0x23:
			type = ConstantInstruction.GLOBAL_GET;
			value = new Leb128(reader);
			break;
		case 0x41:
			type = ConstantInstruction.I32_CONST;
			value = new Leb128(reader);
			break;
		case 0x42:
			type = ConstantInstruction.I64_CONST;
			value = new Leb128(reader);
			break;
		case 0x43:
			type = ConstantInstruction.F32_CONST;
			value = reader.readNextByteArray(4);
			break;
		case 0x44:
			type = ConstantInstruction.F64_CONST;
			value = reader.readNextByteArray(8);
			break;
		case 0xD0: {
			int refTypeCode = reader.readNextUnsignedByte();
			if (refTypeCode == 0x6F) {
				type = ConstantInstruction.REF_NULL_EXTERNREF;
			} else if (refTypeCode == 0x70) {
				type = ConstantInstruction.REF_NULL_FUNCREF;
			} else {
				throw new IllegalArgumentException("Invalid ref.null reftype " + refTypeCode);
			}
			value = null;
			break;
		}
		case 0xD2:
			type = ConstantInstruction.REF_FUNC;
			value = new Leb128(reader);
			break;
		default:
			throw new IllegalArgumentException("Invalid instruction opcode " + typeCode + " in constant expression");
		}

		int end = reader.readNextUnsignedByte();
		if (end != 0x0b) {
			throw new IllegalArgumentException("Missing end byte");
		}
	}

	public ConstantInstruction getInstructionType() {
		return type;
	}

	public Object getRawValue() {
		return value;
	}

	public Long getValueI32() {
		if (type == ConstantInstruction.I32_CONST) {
			return ((Leb128) value).getValue();
		}
		return null;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = StructureUtils.createStructure("expr");
		StructureUtils.addField(structure, BYTE, "opcode");
		switch (type) {
		case I32_CONST:
		case I64_CONST:
		case REF_FUNC:
		case GLOBAL_GET:
			StructureUtils.addField(structure, (Leb128) value, "value");
			break;
		case F32_CONST:
			StructureUtils.addField(structure, Float4DataType.dataType, "value");
			break;
		case F64_CONST:
			StructureUtils.addField(structure, Float8DataType.dataType, "value");
			break;
		case REF_NULL_FUNCREF:
		case REF_NULL_EXTERNREF:
			StructureUtils.addField(structure, BYTE, "nulltype");
			break;
		}
		StructureUtils.addField(structure, BYTE, "end_opcode");
		return structure;
	}
}
