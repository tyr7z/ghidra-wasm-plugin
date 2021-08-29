package wasm.analysis;

import ghidra.program.model.address.Address;

public class ValidationException extends RuntimeException {
	private Address instAddress;

	public ValidationException(Address instAddress, String message) {
		super(message);
		this.instAddress = instAddress;
	}

	@Override
	public String getMessage() {
		return "Validation error at address " + instAddress + ": " + super.getMessage();
	}
}
