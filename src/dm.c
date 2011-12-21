/* dm.c - interface to device mapper API */
#include <stdlib.h>
#include <string.h>
#include <libdevmapper.h>
#include <errno.h>
#include "steg.h"

void dm_check_version(void)
{
	char *saveptr, *version;
	struct dm_task *task = dm_task_create(DM_DEVICE_VERSION);
	if(!task) {
		die("dm_task_create");
	}
	dm_task_run(task);
	version = steg_malloc(1024);
	dm_task_get_driver_version(task, version, 1024);
	version[1023] = 0;
	strtok_r(version, ".", &saveptr);
	if(strncmp(version, MESG_STR("4"))) {
		die("unknown device mapper version");
	}
	steg_free(version);
	dm_task_destroy(task);
}

int dm_message(char *path, char *message)
{
	struct dm_task *task;
	int e = -EIO;
	if(!path) {
		goto fail;
	}
	if(!(task = dm_task_create(DM_DEVICE_TARGET_MSG))) {
		goto fail;
	}
	if(!dm_task_set_name(task, path)) {
		goto fail;
	}
	if(!dm_task_set_sector(task, 0)) {
		goto fail;
	}
	if(!dm_task_set_message(task, message)) {
		goto fail;
	}
	if(!dm_task_run(task)) {
		e = -errno;
		goto fail;
	}
	e = 0;
	fail:
	dm_task_destroy(task);
	return e;
}

int dm_bunnypair(char *path, u8 *old_output, u8 *seed, u8 *output)
{
	int e;
	char *msg = steg_malloc(512);
	strcpy(msg, "bunnypair ");
	sprint_hex(msg + strlen(msg), old_output, BUNNY_ENTRY_BYTES);
	strcat(msg, " ");
	sprint_hex(msg + strlen(msg), seed, BUNNY_ENTRY_BYTES);
	strcat(msg, " ");
	sprint_hex(msg + strlen(msg), output, BUNNY_ENTRY_BYTES);
	e = dm_message(path, msg);
	steg_free(msg);
	return e;
}

int dm_umount_aspect(char *path)
{
	int e = -EIO;
	struct dm_task *task;
	if(!(task = dm_task_create(DM_DEVICE_REMOVE))) {
		goto fail;
	}
	if(!dm_task_set_name(task, path)) {
		goto fail;
	}
	if(!dm_task_run(task)) {
		e = -errno;
		goto fail;
	}
	e = 0;
	fail:
	dm_task_destroy(task);
	return e;
}

int dm_mount_aspect(substrate_t *substrate, u64 header_offset, u8 *header_key, char *name)
{
	char *params;
	struct dm_task *task;
	task = dm_task_create(DM_DEVICE_CREATE);
	if(!task) {
		die("dm_task_create");
	}
	if(!dm_task_set_name(task, name)) {
		die("dm_task_set_name");
	}
	if(!dm_task_set_uuid(task, name)) {
		die("dm_task_set_uuid");
	}
	params = steg_malloc(strlen(substrate->filename) + 4096);
	sprintf(params, "%s %zu ", substrate->filename, header_offset);
	sprint_hex(params + strlen(params), header_key, KEY_BYTES);
	if(!dm_task_add_target(task, 0, substrate->bytes, "steg", params)) {
		die("dm_task_add_target");
	}
	if(!dm_task_run(task)) {
		die("dm_task_run");
	}
	dm_task_destroy(task);
	steg_free(params);
	return 0;
}
