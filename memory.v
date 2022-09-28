module main

// read one type from virtual memory of a given process a handle.
// this function return an optional of the type given
pub fn r<T>(fromProc C.HANDLE, atAddr voidptr) ?T {
	C.VMProtectBeginMutation(c"r")

	mut data := T{}
	mut bytes_read := u16(0)

	if !C.ReadProcessMemory(fromProc, atAddr, &data, sizeof(T), &bytes_read) {
		return error('failed to read data at address: $atAddr')
	}

	C.VMProtectEnd()

	return data
}

// write one type to virtual memory of a given process a handle.
// this functioncan throw
pub fn w<T>(fromProc C.HANDLE, atAddr voidptr, withData &T) ? {

	C.VMProtectBeginMutation(c"mem.w")

	mut bytes_wrote := u16(0)

	if !C.WriteProcessMemory(fromProc, atAddr, withData, sizeof(T), &bytes_wrote) {
		return error('failed to write data at address: $atAddr')
	}

	C.VMProtectEnd()
}

// write one type to virtual memory of a given process a handle.
// this functioncan throw
pub fn wr(fromProc C.HANDLE, atAddr voidptr, withData voidptr, andSize u32) ? {

	C.VMProtectBeginMutation(c"mem.wr")

	mut bytes_wrote := u16(0)

	if !C.WriteProcessMemory(fromProc, atAddr, withData, andSize, &bytes_wrote) {
		return error('failed to write data at address: $atAddr')
	}
	
	C.VMProtectEnd()
}

// read X elements of an array of the type given from virtual memory of a giver process a handle.
// this function return an optional of an array of the type given
pub fn rar<T>(fromProc C.HANDLE, atAddr voidptr, andSize u32, output []T) ? {

	C.VMProtectBeginMutation(c"meme.rar")

	mut bytes_read := u16(0)

	if !C.ReadProcessMemory(fromProc, atAddr, output.data, sizeof(T) * andSize,
		&bytes_read) {
		return error('failed to read data from array with size $andSize at address: $atAddr')
	}

	C.VMProtectEnd()
}

// write an array to virtual memory of a given process a handle.
// this function can throw
pub fn wa<T>(fromProc C.HANDLE, atAddr voidptr, withData []T) ? {

	C.VMProtectBeginMutation(c"mem.wa")

	mut bytes_wrote := u16(0)

	if !C.WriteProcessMemory(fromProc, atAddr, withData.data, sizeof(T) * u32(withData.len),
		&bytes_wrote) {
		return error('failed to write data from array with size $withData.len at address: $atAddr')
	}

	C.VMProtectEnd()
}
