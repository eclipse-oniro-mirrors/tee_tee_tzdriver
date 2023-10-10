#include "agent.h"
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <securec.h>

static struct ca_info g_allowed_ext_agent_ca[] = {
#ifdef CONFIG_TZDRIVER
	{
		"/vendor/bin/hiaiserver",
		3094,
		TEE_SECE_AGENT_ID,
	},
	{
		"/vendor/bin/hw/vendor.huawei.hardware.\
		biometrics.hwfacerecognize@1.1-service",
		1000,
		TEE_FACE_AGENT1_ID,
	},
		{
		"/vendor/bin/hw/vendor.huawei.hardware.\
		biometrics.hwfacerecognize@1.1-service",
		1000,
		TEE_FACE_AGENT2_ID,
	},
#endif
#ifdef DEF_ENG
	{
		"/vendor/bin/tee_test_agent",
		0,
		TEE_SECE_AGENT_ID,
	},
#endif
};

int is_allowed_agent_ca(const struct ca_info *ca,
	bool check_agent_id)
{
	uint32_t i;
	struct ca_info *tmp_ca = g_allowed_ext_agent_ca;
	const uint32_t nr = ARRAY_SIZE(g_allowed_ext_agent_ca);

	if (!ca)
		return -EFAULT;

	if (!check_agent_id) {
		for (i = 0; i < nr; i++) {
			if (!strncmp(ca->path, tmp_ca->path,
				strlen(tmp_ca->path) + 1) &&
				ca->uid == tmp_ca->uid)
				return 0;
			tmp_ca++;
		}
	} else {
		for (i = 0; i < nr; i++) {
			if (!strncmp(ca->path, tmp_ca->path,
					strlen(tmp_ca->path) + 1) &&
					ca->uid == tmp_ca->uid &&
					ca->agent_id == tmp_ca->agent_id)
					return 0;
				tmp_ca++;
		}
	}
	tlogd("ca-uid is %u, ca_path is %s, agent id is %x\n", ca->uid,
		ca->path, ca->agent_id);

	return -EACCES;
}