package wasm.analysis;

import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WasmPreAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Wasm Pre-Analyzer";
	private final static String DESCRIPTION = "Analyze Wasm code before disassembly to resolve operand sizes and jump offsets";

	public WasmPreAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		// run immediately before initial disassembly
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("Webassembly"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) throws CancelledException {
		WasmAnalysis state = WasmAnalysis.getState(program);
		List<WasmFuncSignature> functions = state.getFunctions();
		monitor.initialize(functions.size());
		for (int i = 0; i < functions.size(); i++) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress(i);

			WasmFuncSignature func = functions.get(i);
			if (func.isImport()) {
				continue;
			}

			BinaryReader codeReader = new BinaryReader(new MemoryByteProvider(program.getMemory(), func.getStartAddr()), true);
			WasmFunctionPreAnalysis preAnalysis = new WasmFunctionPreAnalysis(func, codeReader);
			try {
				preAnalysis.analyzeFunction(program, state, monitor);
			} catch (Exception e) {
				Msg.error(this, "Failed to analyze function at index " + i + " (" + func.getName() + ")", e);
			}
		}
		return true;
	}
}
