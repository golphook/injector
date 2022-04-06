module main

import time

fn thread_hijacking_release(hnd_t C.HANDLE, hnd C.HANDLE, code_cave_addr voidptr, resume bool) {
	if resume {
		C.ResumeThread(hnd_t)
	}

	if int(code_cave_addr) != 0 {
		C.VirtualFreeEx(hnd, code_cave_addr, 0, u32(C.MEM_RELEASE))
	}
	C.CloseHandle(hnd_t)
}

fn call_dll_main_via_thread_hijacking(hnd C.HANDLE, proc_id u32, routine voidptr, args voidptr) ? {

	thread := get_thread(proc_id) or {
		return error("An error occured while finding a thread: $err")
	}
	println("[+] using thread $thread.id")

	hnd_t := C.OpenThread(u32(C.THREAD_ALL_ACCESS), false, thread.id)
	if int(hnd_t) == 0 || int(hnd_t) == -1 {
		return error("Invalid thread handle")
	}

	if C.SuspendThread(hnd_t) == -1 {
		return error("failed to suspend thread")
	}

	mut old_thread_context := ThreadContext{}
	old_thread_context.context_flags = u32(C.CONTEXT_CONTROL)

	if !C.GetThreadContext(hnd_t, &old_thread_context) {
		thread_hijacking_release(hnd_t, voidptr(0), voidptr(0), true)
		return error("failed to get thread context")
	}

	code_cave := C.VirtualAllocEx(hnd, voidptr(0), 0x100, u32(C.MEM_COMMIT | C.MEM_RESERVE), u32(C.PAGE_EXECUTE_READWRITE))
	if int(code_cave) == 0 {
		thread_hijacking_release(hnd_t, voidptr(0), voidptr(0), true)
		return error("Failed to allocate memory for shellcode")
	}

	mut shellcode_t := [
		byte(0x00), 0x00, 0x00, 0x00, 0x83, 0xEC, 0x04, 0xC7, 0x04, 0x24, 0x00,
		0x00, 0x00, 0x00, 0x50, 0x51, 0x52, 0x9C, 0xB9, 0x00, 0x00, 0x00, 0x00,
		0xB8, 0x00, 0x00, 0x00, 0x00, 0x51, 0xFF, 0xD0, 0xA3, 0x00, 0x00, 0x00,
		0x00, 0x9D, 0x5A, 0x59, 0x58, 0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC3
	]

	fn_offset := usize(0x4)
	check_byte_offset := 0x2 + fn_offset
	shellcode_data := usize(shellcode_t.data)

	mut a := &usize(shellcode_data + 0x06 + fn_offset)
	unsafe { *a = old_thread_context.eip }

	mut b := &&usize(shellcode_data + 0x0F + fn_offset)
	unsafe { *b = args }

	mut c := &&usize(shellcode_data + 0x14 + fn_offset)
	unsafe { *c = routine }

	mut d := &&usize(shellcode_data + 0x1C + fn_offset)
	unsafe { *d = code_cave }

	mut e := &&byte(shellcode_data + 0x26 + fn_offset)
	unsafe { *e = &byte(usize(code_cave) + check_byte_offset) }

	old_thread_context.eip = u32(usize(code_cave) + fn_offset)

	wr(hnd, code_cave, shellcode_t.data, u32(shellcode_t.len)) or {
		thread_hijacking_release(hnd_t, hnd, code_cave, true)
		return error("failed to write shellcode to target process")
	}
	println("[+] executing")
	if !C.SetThreadContext(hnd_t, &old_thread_context) {
		thread_hijacking_release(hnd_t, hnd, code_cave, true)
		return error("failed to set new thread context")
	}

	if C.ResumeThread(hnd_t) == -1 {
		thread_hijacking_release(hnd_t, hnd, code_cave, false)
		return error("failed to resume thread with new context")
	}


	for t in 0..7 {

		if (r<byte>(hnd, voidptr(usize(code_cave) + check_byte_offset)) ?) != byte(0) {
			println("[+] executed\n")
			break
		}

		if t > 5 {
			return error("it seems that the shellcode failed to be executed :/")
		}

		time.sleep(1 * time.second)
	}
	//thread_hijacking_release(hnd_t, hnd, code_cave, false)
}
