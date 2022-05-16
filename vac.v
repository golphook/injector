module main
import time

fn get_steam_path() ?string {

	h_key := int(0)

	if C.RegOpenKeyExA(C.HKEY_CURRENT_USER, c"Software\\Valve\\Steam", 0, C.KEY_QUERY_VALUE, &h_key) != int(C.ERROR_SUCCESS) {
		C.RegCloseKey(h_key)
		return error("Failed to find steam registry")
	}

	mut path_buff := []u8{len: C.MAX_PATH}
	path_buff[0] = '"'.bytes()[0]

	steam_path_size := u32(C.MAX_PATH - 1)


	if C.RegQueryValueExA(h_key, c"SteamExe", voidptr(0), voidptr(0), &u8(voidptr(usize(path_buff.data) + 1)), &steam_path_size) != int(C.ERROR_SUCCESS) {
		C.RegCloseKey(h_key)
		return error("Failed to get steam path")
	}

	C.RegCloseKey(h_key)

	mut steam_path := unsafe { cstring_to_vstring(voidptr(path_buff.data)) }

	steam_path += '"'

	return steam_path
}

fn load_vac_bypass() ? {
	for is_procss_open("csgo.exe") || is_procss_open("steam.exe") || is_procss_open("steamservice.exe") || is_procss_open("steamwebhelper.exe") {
		kill_process("csgo.exe") or {}
		kill_process("steam.exe") or {}
		kill_process("steamservice.exe") or {}
		kill_process("steamwebhelper.exe") or {}
		time.sleep(100 * time.millisecond)
	}

	steam_exe := get_steam_path() or { return error("$err") }
	println("[*] steam path: $steam_exe")

	println("[-] starting steam...")
	steam_process := create_process(steam_exe, ["-console"]) or { return  error("$err") }
	println("[*] steam pid: $steam_process.process_id")

	if is_procss_open("steamservice.exe") {
		return error("steam did not run as admin")
	}

	println("[-] mapping dll...")
	target_base, routine, args, file_addr := map_dll(steam_process.h_process, "vac3_inhibitor.dll") or {
		return error("An error occured while mapping dll: $err")
	}

	println("[-] executing dll main via thread hijacking...")
	call_dll_main_via_thread_hijacking(steam_process.h_process, steam_process.process_id, routine, args) or {
		return error("An error occured while calling dll main: $err")
	}

	clean(steam_process.h_process, target_base, routine, file_addr) or {
		return error("$err")
	}
}
