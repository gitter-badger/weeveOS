
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <assert.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <eciotify_ta.h>

TEEC_Result start_ta_context();
void stop_ta_context();
int unregister_device();

TEEC_Context ctx;
TEEC_Session sess;


int main(int argc, char *argv[])
{
	printf("######unregister device######\n");
	unregister_device();
}

int unregister_device() 
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	
	res = start_ta_context();
	if (res == TEEC_SUCCESS)
	{
		printf("[NORMAL WORLD] Starting TA done.\n" );
	}

	memset(&op, 0, sizeof(op));
	res = TEEC_InvokeCommand(&sess, TA_DEL_KEYS, &op, &err_origin);
	if (res == TEEC_SUCCESS)
		printf("[NORMAL WORLD] All keys deleted.\n");
	
	stop_ta_context();
	return 0;


}

TEEC_Result start_ta_context()
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_ECIOTIFY_UUID;

	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) 
	{
		printf("[NORMAL WORLD] Starting TA context failed.\n" );
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		printf("[NORMAL WORLD] Starting TA session failed.\n" );
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	}

	return TEEC_SUCCESS;
}

void stop_ta_context()
{
	printf("[NORMAL WORLD] Close session.\n");
	TEEC_CloseSession(&sess);

	printf("[NORMAL WORLD] Finalize Context.\n");
	TEEC_FinalizeContext(&ctx);
}