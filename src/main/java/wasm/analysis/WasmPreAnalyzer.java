package wasm.analysis;

import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WasmPreAnalyzer extends AbstractAnalyzer {
	private final static String NAME = "Wasm Pre-Analyzer";
	private final static String DESCRIPTION = "Analyze Wasm code before disassembly to resolve operand sizes and jump offsets";

	private final static String OPTION_NAME_CSTACK_GLOBAL = "C Stack Pointer";
	private static final String OPTION_DESCRIPTION_CSTACK_GLOBAL = "Index of the global variable being used as the C stack pointer. Set to -1 to disable C stack inference.";
	/* Default to global0, which is what Emscripten appears to do */
	private final static int OPTION_DEFAULT_CSTACK_GLOBAL = 0;
	private int cStackGlobal = OPTION_DEFAULT_CSTACK_GLOBAL;

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
	public void registerOptions(Options options, Program program) {
		HelpLocation helpLocation = new HelpLocation("AutoAnalysisPlugin", "Auto_Analysis_Option_Instructions");

		options.registerOption(OPTION_NAME_CSTACK_GLOBAL, cStackGlobal, helpLocation,
				OPTION_DESCRIPTION_CSTACK_GLOBAL);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		cStackGlobal = options.getInt(OPTION_NAME_CSTACK_GLOBAL, cStackGlobal);
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
			Function function = program.getListing().getFunctionAt(func.getStartAddr());
			if (func.isImport()) {
				continue;
			}

			BinaryReader codeReader = new BinaryReader(new MemoryByteProvider(program.getMemory(), func.getStartAddr()), true);
			WasmFunctionPreAnalysis preAnalysis = new WasmFunctionPreAnalysis(func, cStackGlobal);
			state.setFunctionPreAnalysis(function, preAnalysis);
			try {
				preAnalysis.analyzeFunction(program, codeReader, monitor);
			} catch (Exception e) {
				Msg.error(this, "Failed to analyze function at index " + i + " (" + func.getName() + ")", e);
				function.setComment("WARNING: Wasm pre-analysis failed, output may be incorrect: " + e);
			}
		}
		return true;
	}
}
