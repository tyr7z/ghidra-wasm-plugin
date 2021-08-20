/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wasm;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import wasm.file.WasmModule;
import wasm.format.WasmConstants;
import wasm.format.WasmHeader;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmDataSection;
import wasm.format.sections.WasmExportSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmNameSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmDataSegment;
import wasm.format.sections.structures.WasmFunctionBody;
import wasm.format.sections.structures.WasmImportEntry;
/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class WasmLoader extends AbstractLibrarySupportLoader {

	public final static long HEADER_BASE = 0x10000000;
	public final static long METHOD_ADDRESS = 0x20000000;
	public final static long MODULE_BASE = 0x30000000;
	public final static long IMPORTS_BASE = 0x40000000;
	// ^ this must be later than METHOD_ADDRESS since we assume that program.getFunctions(true) returns non-imported functions first
	public final static long IMPORT_STUB_LEN = 16;

	@Override
	public String getName() {
		return "WebAssembly";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, true);
		WasmHeader header = new WasmHeader(reader);

		if(WasmConstants.WASM_MAGIC_BASE.equals(new String(header.getMagic()))) {
			loadSpecs.add(new LoadSpec(this, 0x10000000,
					new LanguageCompilerSpecPair("Wasm:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	public static Address getImportAddress(Program program, int funcIdx) {
		return getProgramAddress(program, IMPORTS_BASE + IMPORT_STUB_LEN * funcIdx);
	}

	private static Address getProgramAddress(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	public static Data createData(Program program, Listing listing, Address address, DataType dt) {
		try {
			Data d = listing.getDataAt(address);
			if (d == null || !dt.isEquivalent(d.getDataType())) {
				d = DataUtilities.createData(program, address, dt, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			}
			return d;
		} catch (CodeUnitInsertionException e) {
			Msg.warn(WasmLoader.class, "ELF data markup conflict at " + address);
			e.printStackTrace();
		} catch (DataTypeConflictException e) {
			Msg.error(WasmLoader.class, "ELF data type markup conflict:" + e.getMessage());
		}
		return null;
	}

	private void createModuleBlock(Program program, FileBytes fileBytes) {
		Address start = getProgramAddress(program, MODULE_BASE);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".module", start, fileBytes, 0, fileBytes.getSize(), false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Module");
			block.setComment("The full file contents of the Wasm module");
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	private void createHeaderBlock(Program program, FileBytes fileBytes, WasmHeader header) {
		Address start = getProgramAddress(program, HEADER_BASE);
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(".header", start, fileBytes, 0, 8, false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
				block.setSourceName("Wasm Module");
			createData(program, program.getListing(), start, header.toDataType());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void createSectionBlock(Program program, FileBytes fileBytes, WasmSection section) {
		Address start = getProgramAddress(program, HEADER_BASE + section.getSectionOffset());
		try {
			MemoryBlock block = program.getMemory().createInitializedBlock(section.getPayload().getName(), start, fileBytes, section.getSectionOffset(), section.getSectionSize(), false);
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			block.setSourceName("Wasm Section");
			createData(program, program.getListing(), start, section.toDataType());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void createFunctionBodyBlock(Program program, FileBytes fileBytes, String functionName, long offset, long length) throws Exception {
		Address start = getProgramAddress(program, METHOD_ADDRESS + offset);
		MemoryBlock block = program.getMemory().createInitializedBlock(functionName, start, fileBytes, offset, length, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
		block.setSourceName("Wasm Function");
	}

	private void createImportStubBlock(Program program, long length) throws Exception {
		Address address = getProgramAddress(program, IMPORTS_BASE);
		MemoryBlock block = program.getMemory().createUninitializedBlock("import_stubs", address, length, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(true);
	}

	private String getMethodName(WasmNameSection names, WasmExportSection exports, int id) {
		if(names != null) {
			String name = names.getFunctionName(id);
			if(name != null) {
				return "wasm_" + name;
			}
		}

		if(exports != null) {
			WasmExportEntry entry = exports.findMethod(id);
			if (entry != null) {
				return "export_" + entry.getName();
			}
		}
		return "unnamed_function_" + id;
	}

	private void loadCodeSection(Program program, FileBytes fileBytes, WasmModule module, WasmSection section, WasmCodeSection codeSection, TaskMonitor monitor) throws Exception {
		long code_offset = section.getPayloadOffset();
		// The function index space begins with an index for each imported function,
		// in the order the imports appear in the Import Section, if present,
		// followed by an index for each function in the Function Section,
		WasmSection imports = module.getSection(WasmSectionId.SEC_IMPORT);
		int importsOffset = imports == null ? 0 : ((WasmImportSection)imports.getPayload()).getCount();
		WasmSection exports = module.getSection(WasmSectionId.SEC_EXPORT);
		WasmExportSection exportSection = exports == null ? null : (WasmExportSection)exports.getPayload();

		List<WasmFunctionBody> functions = codeSection.getFunctions();
		for (int i = 0; i < functions.size(); ++i) {
			WasmFunctionBody method = functions.get(i);

			String methodName = getMethodName(
				module.getNameSection(),
				exportSection,
				i + importsOffset
			);

			long methodOffset = code_offset + method.getOffset();

			try {
				createFunctionBodyBlock(program, fileBytes, methodName, methodOffset, method.getInstructions().length);
				Address methodAddress = getProgramAddress(program, METHOD_ADDRESS + methodOffset);
				Address methodEnd = getProgramAddress(program, METHOD_ADDRESS + methodOffset + method.getInstructions().length);

				/* TODO: set function type */
				Function function = program.getFunctionManager().createFunction(
						methodName, methodAddress,
						new AddressSet(methodAddress, methodEnd), SourceType.IMPORTED);
				program.getSymbolTable().createLabel(methodAddress, methodName, SourceType.IMPORTED);
			} catch(Exception e) {
				e.printStackTrace();
			}
		}
	}

	private void loadDataSection(Program program, FileBytes fileBytes, WasmSection section, WasmDataSection dataSection, TaskMonitor monitor) throws Exception {
		List<WasmDataSegment> dataSegments = dataSection.getSegments();
		for(int i=0; i<dataSegments.size(); i++) {
			WasmDataSegment dataSegment = dataSegments.get(i);
			long offset = dataSegment.getOffset();
			if(offset == -1)
				continue;
			long fileOffset = dataSegment.getFileOffset() + section.getPayloadOffset();
			Address dataStart = program.getAddressFactory().getAddressSpace("mem0").getAddress(offset);
			MemoryBlock block = program.getMemory().createInitializedBlock(".data" + i, dataStart, fileBytes, fileOffset, dataSegment.getSize(), false);
			/* We have to assume that linear memory is writable */
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
		}
	}

	private void loadImportSection(Program program, FileBytes fileBytes, WasmSection section, WasmImportSection importSection, TaskMonitor monitor) throws Exception {
		createImportStubBlock(program, importSection.getCount() * IMPORT_STUB_LEN);
		int nextFuncIdx = 0;
		for(WasmImportEntry entry : importSection.getEntries()) {
			if(entry.getKind() != WasmExternalKind.EXT_FUNCTION) {
				continue;
			}

			String methodName = "import__" + entry.getName();
			Address methodAddress = getProgramAddress(program, IMPORTS_BASE + nextFuncIdx * IMPORT_STUB_LEN);
			Address methodEnd = getProgramAddress(program,  IMPORTS_BASE + (nextFuncIdx + 1) * IMPORT_STUB_LEN - 1);

			program.getFunctionManager().createFunction(
					methodName, methodAddress,
					new AddressSet(methodAddress, methodEnd), SourceType.IMPORTED);

			program.getSymbolTable().createLabel(methodAddress, methodName, SourceType.IMPORTED);

			nextFuncIdx++;
		}
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
		Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		monitor.setMessage("Wasm Loader: Start loading");

		try {
			doLoad(provider, program, monitor);
		} catch (Exception e) {
			monitor.setMessage("Wasm Loader: Error");
			e.printStackTrace();
		}
	}

	private void doLoad(ByteProvider provider, Program program, TaskMonitor monitor) throws Exception {
		BinaryReader reader = new BinaryReader(provider, true);
		WasmModule module = new WasmModule(reader);

		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, provider.length(), monitor);

		createModuleBlock(program, fileBytes);
		createHeaderBlock(program, fileBytes, module.getHeader());
		for (WasmSection section: module.getSections()) {
			monitor.setMessage("Wasm Loader: Loading section " + section.getId().toString());
			createSectionBlock(program, fileBytes, section);
			try {
				switch(section.getId()) {
					case SEC_CODE:
						loadCodeSection(program, fileBytes, module, section, (WasmCodeSection)section.getPayload(), monitor);
						break;
					case SEC_DATA:
						loadDataSection(program, fileBytes, section, (WasmDataSection)section.getPayload(), monitor);
						break;
					case SEC_IMPORT:
						loadImportSection(program, fileBytes, section, (WasmImportSection)section.getPayload(), monitor);
						break;
				}
			} catch(Exception e) {
				e.printStackTrace();
			}
		}
	}
}
