#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
// #include <time.h>

#include <termios.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <eciotify_ta.h>

TEEC_Result start_ta_context();
void stop_ta_context();
int register_device();
pid_t popen2(const char *command, int *infp, int *outfp);

TEEC_Context ctx;
TEEC_Session sess;


int main(int argc, char *argv[])
{
	printf("###### Register device ######\n");
	register_device();
}

int register_device() 
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	char device_id[128];
	char vk_mqtts[256];
	char vk_testimony[256];
	char vk_blockchain[256+42];
	char command_vk_mqtts[5000];
	char command_vk_testimony[5000];
	char command_vk_blockchain[5000];
	char command_sub[5000];
	char  command_gen_keys[] = "ethwallet generate";
	FILE *fp;
	pid_t program_id;
	FILE *file;

	int go_reply_size = 64 + 130 + 42 + 1;
	char go_reply[go_reply_size];

	res = start_ta_context();
	if (res == TEEC_SUCCESS)
	{
		printf("[NORMAL WORLD] Starting TA done.\n" );
	}

	memset(&op, 0, sizeof(op));
	res = TEEC_InvokeCommand(&sess, TA_GEN_TESTIMONY_KEYS, &op, &err_origin);
	if (res == TEEC_SUCCESS)
		printf("[NORMAL WORLD] Keys TESTIMONY created.\n");

	memset(&op, 0, sizeof(op));
	res = TEEC_InvokeCommand(&sess, TA_GEN_WALLET_KEYS, &op, &err_origin);
	if (res == TEEC_SUCCESS)
		printf("[NORMAL WORLD] Keys WALLET created.\n");

	memset(&op, 0, sizeof(op));
	res = TEEC_InvokeCommand(&sess, TA_GEN_MQTTS_KEYS, &op, &err_origin);
	if (res == TEEC_SUCCESS)
		printf("[NORMAL WORLD] Keys MQTTS created.\n");

	fp = popen(command_gen_keys, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		exit(1);
	}

	while (fgets(go_reply, go_reply_size+1, fp) != NULL)

	printf("%s", go_reply);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = go_reply;
 	op.params[0].tmpref.size = 64;

 	op.params[1].tmpref.buffer = (char*)go_reply+64;
 	op.params[1].tmpref.size = 130;

 	op.params[2].tmpref.buffer = (char*)go_reply+194;
 	op.params[2].tmpref.size = 42;

	res = TEEC_InvokeCommand(&sess, TA_SAVE_BC_KEYS, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);	

	printf("Enter your Device ID: ");
	scanf("%s", device_id);

	memset(vk_mqtts, 0, sizeof(vk_mqtts));
	memset(vk_testimony, 0, sizeof(vk_testimony));
	memset(vk_blockchain, 0, sizeof(vk_blockchain));
	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);

	op.params[0].tmpref.buffer = device_id;
 	op.params[0].tmpref.size = sizeof(device_id);

 	op.params[1].tmpref.buffer = vk_mqtts;
 	op.params[1].tmpref.size = sizeof(vk_mqtts);

 	op.params[2].tmpref.buffer = vk_testimony;
 	op.params[2].tmpref.size = sizeof(vk_testimony);

 	op.params[3].tmpref.buffer = vk_blockchain;
 	op.params[3].tmpref.size = sizeof(vk_blockchain);

	res = TEEC_InvokeCommand(&sess, TA_REGISTER_DEVICE, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	memcpy(vk_blockchain+128, go_reply+194, 42);

	printf("vk_mqtts: (%zu) %s\n", op.params[1].tmpref.size, vk_mqtts);
	printf("vk_testimony: (%zu) %s\n", op.params[2].tmpref.size, vk_testimony);
	printf("vk_blockchain: (%zu) %s\n", op.params[3].tmpref.size, vk_blockchain);

	snprintf(command_sub, 194, "mosquitto_sub -h %s -t electricity/%s/# --keysS &", BROKER_IP, device_id);
	
	program_id = fork();
    if ( program_id == -1 ) {
        perror("fork failed");
        return EXIT_FAILURE;
    }
    else if ( program_id == 0 ) {
        execl("/bin/sh", "bin/sh", "-c", command_sub, NULL);
        return EXIT_FAILURE;
    }
    
    int status;
    if ( waitpid(program_id, &status, 0) == -1 ) {
        perror("waitpid failed");
        return EXIT_FAILURE;
    }
    
	file = fopen("/bin/pid.txt", "w");
	if (file == NULL)
	{
		printf("Error opening file!\n");
	}

	fprintf(file, "%i", program_id+1);
	fclose(file);
	printf("Subscribed to Device-Channel\n");
	sleep(10);
	sprintf(command_vk_mqtts, "mosquitto_pub -h %s -t electricity/%s/register/mqtts -m %s --keysP", BROKER_IP, device_id, vk_mqtts);
	printf("Send MQTTS VK to Gateway\n");
	system(command_vk_mqtts);
	sprintf(command_vk_testimony, "mosquitto_pub -h %s -t electricity/%s/register/testimony -m %s --keysP", BROKER_IP, device_id, vk_testimony);
	printf("Send TESTIMONY VK to Gateway\n");
	system(command_vk_testimony);
	sprintf(command_vk_blockchain, "mosquitto_pub -h %s -t electricity/%s/register/wallet -m %s --keysP", BROKER_IP, device_id, vk_blockchain);
	printf("Send WALLET VK to Gateway\n");
	system(command_vk_blockchain);
	
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