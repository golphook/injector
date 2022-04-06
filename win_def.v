module main

#include "windows.h"
#include "TlHelp32.h"

// hi

[typedef]
struct C.PROCESSENTRY32W {
mut:
	dwSize              u32
	cntUsage            u32
	th32ProcessID       u32
	th32DefaultHeapID   voidptr
	th32ModuleID        u32
	cntThreads          u32
	th32ParentProcessID u32
	pcPriClassBase      u32
	dwFlags             u32
	szExeFile           &char = 0
}

[typedef]
struct C.THREADENTRY32 {
mut:
	dwSize              u32
	cntUsage u32
	th32ThreadID u32
	th32OwnerProcessID u32
	tpBasePri int
	tpDeltaPri int
	dwFlags u32
}
struct FloatingSaveArea {
	control_word u32
	status_word u32
	tag_word u32
	error_offset u32
	error_selector u32
	data_offset u32
	data_selector u32
	register_area [80]u8
	spare0 u32
}

struct ThreadContext {
pub mut:
	context_flags u32
	dr0 u32
	dr1 u32
	dr2 u32
	dr3 u32
	dr6 u32
	dr7 u32
	float_save FloatingSaveArea
	seg_gs u32
	seg_fs u32
	seg_es u32
	seg_ds u32
	edi u32
	esi u32
	ebx u32
	edx u32
	ecx u32
	eax u32
	ebp u32
	eip u32
	seg_cs u32
	e_flags u32
	esp u32
	seg_ss u32
	extended_registers [512]u8
}


fn C.CreateToolhelp32Snapshot(int, int) C.HANDLE
fn C.Process32FirstW(C.HANDLE, voidptr) bool
fn C.Process32NextW(C.HANDLE, voidptr) bool

fn C.Thread32First(C.HANDLE, voidptr) bool
fn C.Thread32Next(C.HANDLE, voidptr) bool

fn C.OpenProcess(u32, bool, u32) C.HANDLE
fn C.OpenThread(u32, bool, u32) C.HANDLE
fn C.CloseHandle(C.HANDLE) bool

fn C.GetThreadContext(C.HANDLE, voidptr) bool
fn C.SetThreadContext(C.HANDLE, voidptr) bool

fn C.SuspendThread(C.HANDLE) u32
fn C.ResumeThread(C.HANDLE) u32

fn C.VirtualAllocEx(C.HANDLE, voidptr, u16, u32, u32) voidptr
fn C.VirtualFreeEx(C.HANDLE, voidptr, u16,u32) bool

fn C.WriteProcessMemory(C.HANDLE, voidptr, voidptr, u16, u16) bool
fn C.ReadProcessMemory(C.HANDLE, voidptr, voidptr, u16, &u16) bool

fn C.GetModuleHandleA(&char) C.HMODULE
fn C.GetProcAddress(C.HMODULE, &char) voidptr

fn C.CreateRemoteThread(C.HANDLE, voidptr, u16, voidptr, voidptr, u32, &u32) C.HANDLE

struct ImageDosHeader
 {
	e_magic u16
	e_cblp u16
	e_cp u16
	e_crlc u16
	e_cparhdr u16
	e_minalloc u16
	e_maxalloc u16
	e_ss u16
	e_sp u16
	e_csum u16
	e_ip u16
	e_cs u16
	e_lfarlc u16
	e_ovno u16
	e_res [4]u16
	e_oemid u16
	e_oeminfo u16
	e_res2 [10]u16
	e_lfanew i32
}

struct ImageDataDirectory {
	virtual_address u32
	size u32
}

struct ImageOptionalHeader {
	magic u16
	major_linker_version u8
	minor_linker_version u8
	size_of_code u32
	size_of_initialized_data u32
	size_of_uninitialized_data u32
	address_of_entry_point u32
	base_of_code u32
	base_of_data u32
	image_base u32
	section_alignment u32
	file_alignment u32
	major_operating_system_version u16
	minor_operating_system_version u16
	major_image_version u16
	minor_image_version u16
	major_subsystem_version u16
	minor_subsystem_version u16
	win32_version_value u32
	size_of_image u32
	size_of_headers u32
	check_sum u32
	subsystem u16
	dll_characteristics u16
	size_of_stack_reserve u32
	size_of_stack_commit u32
	size_of_heap_reserve u32
	size_of_heap_commit u32
	loader_flags u32
	number_of_rva_and_sizes u32
	data_directory [16]ImageDataDirectory
}

struct ImageFileHeader {
	machine u16
	number_of_sections u16
	time_date_stamp u32
	pointer_to_symbol_table u32
	number_of_symbols u32
	size_of_optional_header u16
	characteristics u16
}

struct ImageNtHeaders {
	signature u32
	file_header ImageFileHeader
	optional_header ImageOptionalHeader
}

struct ImageSectionHeader {
	name [8]byte
	physical_address u32
	virtual_size_or_address u32
	size_of_raw_data u32
	pointer_to_raw_data u32
	pointer_to_relocations u32
	pointer_to_linenumbers u32
	number_of_relocations u16
	number_of_linenumbers u16
	characteristics u32
}

struct ImageBaseRelocation {
	virtual_address u32
	size_of_block u32
}

struct ImageImportDescriptor {
	characteristics_or_og_first_thunks u32
	time_date_stamp u32
	forwarder_chain u32
	name u32
	first_thunks u32
}

struct ImportImageByName {
	hint u16
	name [1]byte
}

struct ImageTlsDirectory {
	start_address_of_raw_data u32
	end_address_of_raw_data u32
	address_of_index u32
	address_of_callback u32
	size_of_zero_fill u32
	characteristics u32
}
