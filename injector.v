module main
import os

fn main() {
	println("[*] Hi golphook :)")

	target_procc := get_process(target_name) or {
		panic("An error occured while retrievinng $target_name process info: $err")
	}

	hnd := C.OpenProcess(u32(C.PROCESS_ALL_ACCESS), false, target_procc.id)
	if int(hnd) == 0 || int(hnd) == -1 {
		panic("Failed to open a handle on target procces: $target_name")
	}

	println("[-] mapping dll...")
	routine, args := map_dll(hnd) or {
		panic("An error occured while mapping dll: $err")
	}

	println("[-] executing dll main via thread hijacking...")
	call_dll_main_via_thread_hijacking(hnd, target_procc.id, routine, args) or {
		panic("An error occured while calling dll main: $err")
	}

	C.CloseHandle(hnd)

	println("[*] done !")
	os.input("")
}

// [windows_stdcall]
// fn shell_code(mut data &InjectData) {
// 	if int(data) == 0 {
// 		return
// 	}
//
// 	base := &usize(data)
//
// 	img_dos := &ImageDosHeader(base)
// 	nt_header := &ImageNtHeaders(usize(base) + usize(img_dos.e_lfanew))
//
// 	load_lib_a := &P_load_liba(data.load_lib_a)
// 	get_proc_addr := &P_get_proc_addr(data.get_proc_addr)
// 	dll_main := &P_dll_entry(base + nt_header.optional_header.address_of_entry_point)
//
// 	loc_delta := &usize(base + nt_header.optional_header.image_base)
// 	if usize(loc_delta) != 0 {
//
// 		if nt_header.optional_header.data_directory[5].size == 0 {
// 			return
// 		}
//
// 		mut reloc_data := &ImageBaseRelocation(base + nt_header.optional_header.data_directory[5].virtual_address)
// 		for reloc_data.virtual_address != 0 {
//
// 			mut entry_ammount := reloc_data.size_of_block - sizeof(ImageBaseRelocation) / sizeof(u16)
// 			mut relative_info := &u16(usize(reloc_data) + 1) // si marche pas mettre + sizeof(ImageBaseRelocation)
//
// 			for i in 0..entry_ammount { // si marche pas mettre + 1
//
// 				if (unsafe { *relative_info } >> 0x0C) == 3 {
// 					patch := &u32(base + reloc_data.virtual_address + ((unsafe { *relative_info }) & 0xFFF))
// 					unsafe { *patch += u32(loc_delta) }
// 				}
//
// 				relative_info = &u16(usize(relative_info) + sizeof(u16))
// 			}
// 			reloc_data = &ImageBaseRelocation(usize(reloc_data) + reloc_data.size_of_block)
// 		}
// 	}
//
// 	if nt_header.optional_header.data_directory[1].size != 0 {
// 		mut import_descriptor := &ImageImportDescriptor(base + nt_header.optional_header.data_directory[1].virtual_address)
// 		for import_descriptor.name != 0 {
// 			sz_mod := &char(base + import_descriptor.name)
// 			h_dll := load_lib_a(sz_mod)
//
// 			mut thunk_ref := &u32(base + import_descriptor.characteristics_or_og_first_thunks)
// 			mut func_ref := &u32(base + import_descriptor.first_thunks)
//
// 			if usize(thunk_ref) == 0 {
// 				thunk_ref = func_ref
// 			}
//
// 			for unsafe { *thunk_ref } != 0 {
//
//
// 				if unsafe { (*thunk_ref & u32(0x80000000)) != 0 } {
// 					unsafe { *thunk_ref = get_proc_addr(h_dll, &char(*thunk_ref & 0xFFFF)) }
// 				} else {
// 					import_ := &ImportImageByName(base + unsafe { *thunk_ref })
// 					unsafe { *thunk_ref = get_proc_addr(h_dll, &char(import_.name)) }
// 				}
// 			}
// 			import_descriptor =  &ImageImportDescriptor(usize(import_descriptor) + sizeof(ImageImportDescriptor))
// 			unsafe { thunk_ref = &u32(usize(thunk_ref) + sizeof(u32)) }
// 			unsafe { func_ref = &u32(usize(func_ref) + sizeof(u32)) }
// 		}
// 	}
//
// 	if nt_header.optional_header.data_directory[9].size != 0 {
// 		tls := &ImageTlsDirectory(base + nt_header.optional_header.data_directory[9].virtual_address)
// 		mut callback := &&P_dll_entry(tls.address_of_callback)
// 		for int(callback) != 0 && int(unsafe { *callback }) != 0 {
// 			t_callback := unsafe {*callback}
// 			unsafe { t_callback(base, u32(C.DLL_PROCESS_ATTACH), voidptr(0)) }
// 			callback = &&P_dll_entry( usize(callback) + sizeof(P_dll_entry) )
// 		}
// 	}
//
// 	dll_main(base, u32(C.DLL_PROCESS_ATTACH), voidptr(0))
// 	data.h_mod = voidptr(base)
//
// }
