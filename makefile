project_name = injector

cc_options=-m32
cc=-cc cl $(cc_options)

temp_path=%temp%
temp_project_path=$(temp_path)\$(project_name)
bin_folder=$(temp_project_path)\build

move_to_temp=xcopy /e /y * $(temp_project_path) &&
move_back=&& del $(temp_project_path)\*.c.exp && del $(temp_project_path)\*.c.lib && xcopy /e /y $(temp_project_path)\* .

build-prod:
	$(move_to_temp) v $(cc) -prod -autofree -skip-unused -gc none -o $(bin_folder)\$(project_name) $(temp_project_path) $(move_back)
build-debug:
	$(move_to_temp) v $(cc) -g -autofree -skip-unused -o $(bin_folder)\$(project_name)-debug.exe $(temp_project_path) $(move_back)
debug-c:
	$(move_to_temp) v $(cc) -autofree -skip-unused -o $(bin_folder)\$(project_name)-debug.c $(temp_project_path)  $(move_back)
debug-cp:
	$(move_to_temp) v $(cc) -prod -o $(bin_folder)\$(project_name)-debug.c $(temp_project_path)  $(move_back)
fmt:
	$(move_to_temp) v fmt -w . $(move_back)

ci-build-prod:
	v $(cc) -prod -autofree -os windows -m32 -o build\$(project_name).exe .
ci-build-debug:
	v $(cc) -g -autofree -os windows -m32 -o build\$(project_name)-debug.exe .
