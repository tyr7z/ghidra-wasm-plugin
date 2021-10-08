package wasm.analysis;

import ghidra.app.plugin.core.analysis.DWARFAnalyzer;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProviderFactory;
import ghidra.program.model.listing.Program;
import wasm.WasmLoader;

public class WasmDWARFAnalyzer extends DWARFAnalyzer {

	@Override
	public boolean canAnalyze(Program program) {
		String format = program.getExecutableFormat();

		if (WasmLoader.WEBASSEMBLY.equals(format)
				&& DWARFSectionProviderFactory.createSectionProviderFor(program) != null) {
			return true;
		}
		return false;
	}
}