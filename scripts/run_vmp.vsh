import os

mut proj_file_text := ""
mut og_proj_file_text := "" 
mut to_be_compiled_proj_path := os.norm_path("ressources/golphook.dll.vmp")
if os.args[1] == "load" {
	to_be_compiled_proj_path = os.norm_path("ressources/golp.exe.vmp")
	proj_file_text = os.read_file(to_be_compiled_proj_path) ?
	og_proj_file_text = proj_file_text 
	proj_file_text = proj_file_text.replace("golp.exe", os.norm_path("../build/golp.exe"))
} else {
	proj_file_text = os.read_file(to_be_compiled_proj_path) ?
	og_proj_file_text = proj_file_text 
	proj_file_text = proj_file_text.replace("golphook.dll", os.norm_path("../ressources/golphook.dll"))

}

os.write_file(to_be_compiled_proj_path, proj_file_text) ?

res := execute("VMProtect_Con $to_be_compiled_proj_path")
dump(res.output)

os.write_file(to_be_compiled_proj_path, og_proj_file_text) ?

