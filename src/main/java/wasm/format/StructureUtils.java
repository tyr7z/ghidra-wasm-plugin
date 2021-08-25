package wasm.format;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class StructureUtils {
    public static Structure createStructure(String name) {
        CategoryPath path = new CategoryPath(CategoryPath.ROOT, "Wasm");
        return new StructureDataType(path, name, 0);
    }

    public static void addField(Structure structure, DataType dataType, String name, String comment) {
        structure.add(dataType, dataType.getLength(), name, comment);
    }

    public static void addField(Structure structure, DataType dataType, String name) {
        addField(structure, dataType, name, null);
    }

    public static void addField(Structure structure, StructConverter converter, String name, String comment) throws DuplicateNameException, IOException {
        addField(structure, converter.toDataType(), name, comment);
    }

    public static void addField(Structure structure, StructConverter converter, String name) throws DuplicateNameException, IOException {
        addField(structure, converter.toDataType(), name, null);
    }

    public static void addArrayField(Structure structure, DataType dataType, int numElements, String name, String comment) {
        if (numElements > 0)
            structure.add(new ArrayDataType(dataType, numElements, dataType.getLength()), name, comment);
    }

    public static void addArrayField(Structure structure, DataType dataType, int numElements, String name) {
        addArrayField(structure, dataType, numElements, name, null);
    }

    public static void addStringField(Structure structure, int byteSize, String name, String comment) {
        if (byteSize > 0)
            structure.add(StructConverter.STRING, byteSize, name, comment);
    }

    public static void addStringField(Structure structure, int byteSize, String name) {
        addStringField(structure, byteSize, name, null);
    }
}
