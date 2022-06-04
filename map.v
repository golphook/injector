module main
import rand

import v.embed_file

#flag -I @VMODROOT/c
#include "macro.h"
#include "shellcode.h"

fn C.image_first_section(voidptr) voidptr

// hi

struct InjectData {
pub mut:
	load_lib_a voidptr
	get_proc_addr voidptr
	h_mod voidptr
}

fn map_dll_release(hnd C.HANDLE, image voidptr, shellcode voidptr) {
	if int(image) != 0 {
		C.VirtualFreeEx(hnd, image, 0, u32(C.MEM_RELEASE))
	}
	if int(shellcode) != 0 {
		C.VirtualFreeEx(hnd, shellcode, 0, u32(C.MEM_RELEASE))
	}
}

fn map_dll(hnd C.HANDLE, and_name string) ?(voidptr, voidptr, voidptr, voidptr) {

	mut file := embed_file.EmbedFileData{compressed: 0, uncompressed: 0}

	match and_name {
		"golphook.dll" {
			file = $embed_file("ressources/golphook.dll")
		}
		"cool_dll.dll" {
			file = $embed_file("ressources/cool_dll.dll")
		}
		// "vac3_inhibitor.dll" {
		// 	file = $embed_file("ressources/vac3_inhibitor.dll")
		// }
		else {}
	}

	base_file_addr := file.data()

	img_dos := unsafe { &ImageDosHeader(base_file_addr) }

	if img_dos.e_magic != 0x5A4D {
		return error("Invalid file")
	}

	nt_header := &ImageNtHeaders(usize(base_file_addr) + usize(img_dos.e_lfanew))

	println("[-] allocating memory for image")
	mut target_base := C.VirtualAllocEx(hnd, voidptr(nt_header.optional_header.image_base), nt_header.optional_header.size_of_image, u32(C.MEM_COMMIT | C.MEM_RESERVE), u32(C.PAGE_EXECUTE_READWRITE))
	if int(target_base) == 0 {
		target_base = C.VirtualAllocEx(hnd, voidptr(0), nt_header.optional_header.size_of_image, u32(C.MEM_COMMIT | C.MEM_RESERVE), u32(C.PAGE_EXECUTE_READWRITE))
		if int(target_base) == 0 {
			return error("Failed to allocate memory $C.GetLastError()")
		}
	}

	println("[+] image base -> ${target_base.str()}")

	mut injection_data := InjectData {}
	injection_data.load_lib_a = voidptr(C.LoadLibraryA)
	injection_data.get_proc_addr = voidptr(C.GetProcAddress)

	println("[+] mapping sections and shellcodes...")
	mut section_header := &ImageSectionHeader(C.image_first_section(voidptr(nt_header)))
	for _ in 0..nt_header.file_header.number_of_sections {
		section_name := unsafe { cstring_to_vstring(voidptr(&section_header.name[0])) }
		if section_header.size_of_raw_data == 0 {
			continue
		}
		to_map_addr := voidptr((usize(target_base) + section_header.virtual_size_or_address))
		from_buff_addr :=  voidptr((usize(base_file_addr) + section_header.pointer_to_raw_data))
		buff_size := section_header.size_of_raw_data
		println("[+] mapping section: $section_name > ${to_map_addr.str()} ($buff_size)")
		wr(hnd, to_map_addr, from_buff_addr, buff_size) or {
			map_dll_release(hnd, target_base, voidptr(0))
			return error("failed to map section $section_name")
		}

		section_header = &ImageSectionHeader(usize(section_header) + sizeof(ImageSectionHeader))
	}
	wr(hnd, target_base, base_file_addr, 0x1000) or {
		map_dll_release(hnd, target_base, voidptr(0))
		return error("failed to map file header")
	}
	wr(hnd, target_base, &injection_data, sizeof(injection_data)) or {
		map_dll_release(hnd, target_base, voidptr(0))
		return error("failed to map injection data")
	}

	println("[+] allocating memory for shellcodes")
	shell_code_addr := C.VirtualAllocEx(hnd, voidptr(0), 0x1000, u32(C.MEM_COMMIT | C.MEM_RESERVE), u32(C.PAGE_EXECUTE_READWRITE))
	if int(shell_code_addr) == 0 {
		map_dll_release(hnd, target_base, voidptr(0))
		return error("failed to allocate memory for shellcode")
	}
	println("[+] writting shellcodes")
	wr(hnd, shell_code_addr, C.shellcode_m, 0x1000) or {
		map_dll_release(hnd, target_base, shell_code_addr)
		return error("faild to write shellcode")
	}

	println("[+] entrypoint ${voidptr(usize(target_base) + usize(nt_header.optional_header.address_of_entry_point)).str()}\n")

	return target_base, shell_code_addr, target_base, base_file_addr
	//C.CreateRemoteThread(hnd, voidptr(0), 0, shell_code_addr, target_base, 0, voidptr(0))
}

fn clean(hnd C.HANDLE, target_base voidptr, shellcode voidptr, base_file_addr voidptr) ? {
	mut junk := []byte{len: 1024 * 1024 * 20}.map(rand.byte())
	//mut junk := []byte{len: 1024 * 1024 * 20}.map(1)

	println("[+] clearing pe header")
	wr(hnd, target_base, junk.data, 0x1000) or {
		map_dll_release(hnd, voidptr(0), shellcode)
		return error("failed to clear pe head")
	}

	img_dos := unsafe { &ImageDosHeader(base_file_addr) }
	nt_header := &ImageNtHeaders(usize(base_file_addr) + usize(img_dos.e_lfanew))
	println("[+] errasing useless sections")
	mut section_header := &ImageSectionHeader(C.image_first_section(voidptr(nt_header)))
	for _ in 0..nt_header.file_header.number_of_sections {
		section_name := unsafe { cstring_to_vstring(voidptr(&section_header.name[0])) }
		if section_header.size_of_raw_data == 0 {
			continue
		}
		if section_name in to_clear {
			to_map_addr := voidptr((usize(target_base) + section_header.virtual_size_or_address))
			from_buff_addr := junk.data
			buff_size := section_header.size_of_raw_data
			println("[+] erasing section: $section_name > ${to_map_addr.str()} ($buff_size)")
			wr(hnd, to_map_addr, from_buff_addr, buff_size) or {
				return error("failed to clear section $section_name")
			}
		}
		section_header = &ImageSectionHeader(usize(section_header) + sizeof(ImageSectionHeader))
	}
	println("")
	//println("[+] freeing shellcode \n")
	//map_dll_release(hnd, voidptr(0), shellcode)

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
