module main

struct Thread {
	id        u32
	process_owner_id u32
	priority int
}

struct Process {
	name      string
	id        u32
}

fn get_process(withProcessName string) ?Process {
	th := C.CreateToolhelp32Snapshot(C.TH32CS_SNAPPROCESS, 0)
	if int(th) == C.INVALID_HANDLE_VALUE {
		error('Failed to open CreateToolhelp32Snapshot handle')
	}
	mut pe := C.PROCESSENTRY32W{
		dwSize: sizeof(C.PROCESSENTRY32)
	}
	if !C.Process32FirstW(th, &pe) {
		C.CloseHandle(th)
		return error('Failed to access first process in list')
	}

	for C.Process32NextW(th, &pe) {
		if unsafe { string_from_wide(&u16(pe.szExeFile)) == withProcessName } {
			C.CloseHandle(th)
			return Process {
				name: unsafe { string_from_wide(&u16(pe.szExeFile)) },
				id: pe.th32ProcessID
			}
		}
	}
	C.CloseHandle(th)
	return error('failed to get pid of process with name: $withProcessName')
}

fn get_thread(withProcessId u32) ?Thread {
	th := C.CreateToolhelp32Snapshot(C.TH32CS_SNAPTHREAD, int(withProcessId))
	if int(th) == C.INVALID_HANDLE_VALUE {
		error('Failed to open CreateToolhelp32Snapshot handle')
	}
	mut te := C.THREADENTRY32{
		dwSize: sizeof(C.THREADENTRY32)
	}
	if !C.Thread32First(th, &te) {
		C.CloseHandle(th)
		return error('Failed to access first thread in list')
	}

	for C.Thread32Next(th, &te) {
		if te.th32OwnerProcessID == withProcessId {
			C.CloseHandle(th)
			return Thread {
				id: te.th32ThreadID,
				process_owner_id: te.th32OwnerProcessID,
				priority: te.tpBasePri
			}
		}
	}
	C.CloseHandle(th)
	return error('failed to get thread for process id: $withProcessId ')
}

fn kill_process(with_name string) ? {

	process := get_process(with_name) ?

	p_handle := C.OpenProcess(C.PROCESS_TERMINATE, false, process.id)

	if !C.TerminateProcess(voidptr(p_handle), 9) {
		return error("failed to close $with_name")
	}

}

fn create_process(with_path string, with_args []string) ?ProcessInformation {

	startup_info := StartupInfoA{}
	process_info := ProcessInformation{}

	mut final_path := with_path

	for args in with_args {
		final_path += " $args"
	}

	if !C.CreateProcessA(voidptr(0), &char(final_path.str), voidptr(0), voidptr(0), false, 0, voidptr(0), voidptr(0), &startup_info, &process_info) {
		return error("failed to start process")
	}

	return process_info

}

fn is_procss_open(with_name string) bool {
	_ := get_process(with_name) or { return false }
	return true
}
