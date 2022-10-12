module main

import net.http
import json

struct Release {
	tag_name string
}

fn check_for_update() ?(bool, bool) {

	$if prod { C.VMProtectBeginMutation(c"update_check") }

	mut branch := latest_version.split("-")[1]

	is_beta := branch == "beta"

	resp_text := http.get_text("https://api.github.com/repos/golphook/golphook/releases")
	mut releases := json.decode([]Release, resp_text) ?
	releases = releases.filter(it.tag_name.contains(branch))
	latest_release := releases[0] or { panic("no available build for $branch branch") }
	
	//dump(latest_release.tag_name)
	//dump(latest_version)

	if latest_release.tag_name != latest_version {
		return true, is_beta
	} 

	$if prod { C.VMProtectEnd() }

	return false, is_beta
}
