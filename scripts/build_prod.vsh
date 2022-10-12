import v.vmod
import json
import net.http
import os
import szip

struct Release {
	tag_name string
}

println("[*] setup build")

mut ls := os.ls(".") ?
if "build" !in ls {
	os.mkdir("build") ?
}
if "tmp" !in ls {
	os.mkdir("tmp") ?
}

branch := os.args[1] or { "prod" }
if branch !in ["beta", "alpha", "prod"] {
	panic("Invalid branch")
}

println("[+] fetching latest release tag...")
resp_text := http.get_text("https://api.github.com/repos/golphook/golphook/releases")
mut releases := json.decode([]Release, resp_text) ?
releases = releases.filter(it.tag_name.contains(branch))
if releases.len == 0 {
	panic("no build available for $branch branch")
}
mut tag := releases[0].tag_name

println("[+] downloading latest release ($tag)")
http.download_file("https://github.com/golphook/golphook/releases/download/$tag/release.zip", os.norm_path("tmp/golphook.zip")) ?

println("[+] extracting dll to ressources folder")
mut z := szip.open(os.norm_path("tmp/golphook.zip"), .default_compression, .read_only) ?
z.open_entry("golphook.dll") ?
z.extract_entry(os.norm_path("ressources/golphook.dll")) ?

println("[+] writing latest version in const.v")
mut cst := os.read_file("consts.v") ?
old_cst := cst
//mut trimmed_tag := tag.split("-")
//trimmed_tag.delete_last()
cst = cst.replace("to_rep_ci", tag)
os.write_file("consts.v", cst) ?

os.input("waiting for dll to be vmprotected...")

mut ls_res := os.ls(os.norm_path("ressources/")) ?

if "golphook.vmp.dll" in ls_res {
	println("[*] found vmp build, renaming...")
	os.mv(os.norm_path("ressources/golphook.vmp.dll"), os.norm_path("ressources/golphook.dll")) ?
}

println("[+] building")
execute("${@VEXE} -prod -autofree -os windows -m32 . -o ${os.norm_path("build/golp.exe")}")

os.input("waiting for loader to be vmprotected...")

mut ls_build := os.ls(os.norm_path("build/")) ?

if "golp.vmp.exe" in ls_build {
	println("[*] found vmp build, renaming...")
	os.mv(os.norm_path("build/golp.vmp.exe"), os.norm_path("build/golp.exe")) ?
}

println("[*] building artifact")
zip_name := match branch {
	"beta" { "golphook-beta.zip" }
	"prod" { "golphook.zip" }
	"nightly" {"golphook-nightly.zip"}
	else { "golphook.zip" }
}
szip.zip_files([os.norm_path("build/golp.exe")], os.norm_path("build/$zip_name")) ?

println("[*] cleaning")
os.write_file("consts.v", old_cst) ?

ls_build = os.ls(os.norm_path("build/")) ?
ls_res = os.ls(os.norm_path("ressources/")) ?

for f in ls_build {
	if f  !in ["golphook.zip", "golphook-beta.zip"] {
		os.rm(os.norm_path("build/${f}")) or {}
	}
}

for f in ls_res {
	if f !in ["cool_dll.dll", "golp.exe.vmp", "golphook.dll.vmp"] {
		os.rm(os.norm_path("ressources/${f}")) or {}
	}
}

os.rmdir_all("tmp") ?
//os.rmdir_all("build") ?


