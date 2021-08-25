package wasm.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import wasm.format.sections.*;
import wasm.format.sections.WasmSection.WasmSectionId;

public class WasmModule {

	private WasmHeader header;
	private List<WasmSection> sections = new ArrayList<>();
	private List<WasmCustomSection> customSections = new ArrayList<>();
	private Map<WasmSectionId, WasmSection> sectionMap = new EnumMap<>(WasmSectionId.class);

	public WasmModule(BinaryReader reader) throws IOException {
		header = new WasmHeader(reader);
		while (reader.getPointerIndex() < reader.length()) {
			WasmSection section = WasmSection.createSection(reader);
			if (section == null)
				continue;
			sections.add(section);

			/* Except for custom sections, all other sections may appear at most once. */
			if (section.getId() == WasmSectionId.SEC_CUSTOM) {
				customSections.add((WasmCustomSection) section);
			} else {
				sectionMap.put(section.getId(), section);
			}
		}
	}

	public List<WasmCustomSection> getCustomSections() {
		return Collections.unmodifiableList(customSections);
	}

	public WasmNameSection getNameSection() {
		for (WasmCustomSection section : customSections) {
			if (section instanceof WasmNameSection) {
				return (WasmNameSection) section;
			}
		}
		return null;
	}

	public WasmTypeSection getTypeSection() {
		return (WasmTypeSection) sectionMap.get(WasmSectionId.SEC_TYPE);
	}

	public WasmImportSection getImportSection() {
		return (WasmImportSection) sectionMap.get(WasmSectionId.SEC_IMPORT);
	}

	public WasmFunctionSection getFunctionSection() {
		return (WasmFunctionSection) sectionMap.get(WasmSectionId.SEC_FUNCTION);
	}

	public WasmTableSection getTableSection() {
		return (WasmTableSection) sectionMap.get(WasmSectionId.SEC_TABLE);
	}

	public WasmLinearMemorySection getLinearMemorySection() {
		return (WasmLinearMemorySection) sectionMap.get(WasmSectionId.SEC_LINEARMEMORY);
	}

	public WasmGlobalSection getGlobalSection() {
		return (WasmGlobalSection) sectionMap.get(WasmSectionId.SEC_GLOBAL);
	}

	public WasmExportSection getExportSection() {
		return (WasmExportSection) sectionMap.get(WasmSectionId.SEC_EXPORT);
	}

	public WasmStartSection getStartSection() {
		return (WasmStartSection) sectionMap.get(WasmSectionId.SEC_START);
	}

	public WasmElementSection getElementSection() {
		return (WasmElementSection) sectionMap.get(WasmSectionId.SEC_ELEMENT);
	}

	public WasmCodeSection getCodeSection() {
		return (WasmCodeSection) sectionMap.get(WasmSectionId.SEC_CODE);
	}

	public WasmDataSection getDataSection() {
		return (WasmDataSection) sectionMap.get(WasmSectionId.SEC_DATA);
	}

	public WasmHeader getHeader() {
		return header;
	}

	public List<WasmSection> getSections() {
		return sections;
	}
}
