module main
import os

fn main() {
	println("[*] Hi golphook :)\n")

	target_procc := get_process(target_name) or {
		panic("An error occured while retrievinng $target_name process info: $err")
	}

	hnd := C.OpenProcess(u32(C.PROCESS_ALL_ACCESS), false, target_procc.id)
	if int(hnd) == 0 || int(hnd) == -1 {
		panic("Failed to open a handle on target procces: $target_name")
	}

	println("[-] mapping dll...")
	target_base, routine, args, file_addr := map_dll(hnd) or {
		panic("An error occured while mapping dll: $err")
	}

	println("[-] executing dll main via thread hijacking...")
	call_dll_main_via_thread_hijacking(hnd, target_procc.id, routine, args) or {
		panic("An error occured while calling dll main: $err")
	}

	println("[-] cleaning after the golp...")
	clean(hnd, target_base, routine, file_addr) or {
		panic("$err")
	}

	C.CloseHandle(hnd)

	println("[*] done !")
	os.input("")
}
