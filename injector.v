module main
import time

fn main() {
	$if prod { C.VMProtectBeginMutation(c"main") }
	
	println("[*] Hi golphook :)\n")

	is_new_version := check_for_update() or { panic("$err") }

	if is_new_version {
		print("[*] a new client is available !")
		time.sleep(7 * time.second)
		exit(1)
	}

	// println("[+] loading vac bypass...")
	// load_vac_bypass() or {
	// 	panic("An error occured while loading vac bypass $err")
	// }
	//
	// println("\n[+] waiting for csgo...")
	// for !is_procss_open("csgo.exe") {
	// 	time.sleep(1 * time.second)
	// }

	println("\n[+] injecting golphook...\n")
	target_procc := get_process(target_name) or {
		panic("An error occured while retrievinng $target_name process info: $err")
	}

	hnd := C.OpenProcess(u32(C.PROCESS_ALL_ACCESS), false, target_procc.id)
	if int(hnd) == 0 || int(hnd) == -1 {
		panic("Failed to open a handle on target procces: $target_name")
	}

	println("[-] mapping dll...")
	target_base, routine, args, file_addr := map_dll(hnd, "golphook.dll") or {
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
	time.sleep(7 * time.second)

	$if prod { C.VMProtectEnd() }
}
