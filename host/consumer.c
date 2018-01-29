
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <assert.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <eciotify_ta.h>

TEEC_Result start_ta_context();
void stop_ta_context();
int getch(void);
int consumer();
void * get_pc () {return __builtin_return_address(0);}

TEEC_Context ctx;
TEEC_Session sess;

int main(int argc, char *argv[])
{
	printf("###### Consumer Client ######\n");
	consumer();
	return 0;
}

int consumer()
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	void *startFor, *endFor, *startMeasure, *endMeasure, *startInput, *endInput;
	int differenceInBytes;
	char offer[1500];
	char signature[129];
	char command_send_demand[5000];
	char command_sub[5000];
	int counter = 20;
	int j = 0;
	int z = 0;
	int k = 0;
	int amountT;
	int priceT;
	int character;
	uint32_t offer_len = sizeof(offer);
	uint32_t signature_len = sizeof(signature);
	char *device_id = NULL;
	uint32_t device_id_len = 128;
	char *sign_output;
	char *offer_output;
	pid_t program_id, pid;
	int sub_is_running;
	FILE *file;

	TEEC_SharedMemory in_shm = {
		.flags = TEEC_MEM_INPUT
	};

	res = start_ta_context();
	if (res == TEEC_SUCCESS)
		printf("[NORMAL WORLD] Context created.\n" );

	device_id = malloc(device_id_len);

	memset(&op, 0, sizeof(op));
	memset(offer, 0, sizeof(offer));
	memset(signature, 0, sizeof(signature));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = device_id;
 	op.params[0].tmpref.size = device_id_len;

	res = TEEC_InvokeCommand(&sess, TA_GET_DEVICE_ID, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

	startInput = get_pc();
	printf("Enter 'q' to abort or any other key to continue charging: \n");
	counter = 20;
	printf("DISCHARGING...\n");
	do 
	{
		startFor = get_pc();
		counter--;
		printf("[");
		for (j=0;j<counter;j++)
			printf("=");
		for (k=j;k<20;k++)
			printf(".");
		printf("]");
		z = (100/20*counter);
		printf("%3d%%", z);
		if(z == 0)
		{
			printf(" [EMPTY]\n");
			break;
		}
		printf("\r");
		fflush(stdout);
		j++;
		endFor = get_pc();

		startMeasure = get_pc();
	    differenceInBytes = (endFor - startFor) / sizeof(long long int) + sizeof(counter); //plus einmal für das i 

	    //allocate shared memmory
		in_shm.buffer = calloc(differenceInBytes-sizeof(counter), sizeof(long long int));
		in_shm.size = differenceInBytes;

		res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
		if (res != TEEC_SUCCESS)
			printf("[NORMAL WORLD] Allocation error with code 0x%x\n", res);

		//fill in the SHḾ
		for (int i = 0; i < differenceInBytes-sizeof(counter); i++)
		{
			memcpy(((long long int *)in_shm.buffer)+i, startFor+i*sizeof(long long int), sizeof(long long int));
		}

		memcpy(((long long int *)in_shm.buffer)+(differenceInBytes-sizeof(counter)), &counter, sizeof(counter));

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE);

		//setting params
		op.params[0].memref.parent = &in_shm;
		op.params[0].memref.size = differenceInBytes;
		op.params[0].memref.offset = 0;
		op.params[1].value.a = differenceInBytes;
		op.params[2].value.a = 0;

		res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CHECK_MEMORY_REGION, &op, &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		
		TEEC_ReleaseSharedMemory(&in_shm);

		//Measure Function
		endMeasure = get_pc();
		differenceInBytes = (endMeasure - startMeasure) / sizeof(long long int);
		in_shm.buffer = calloc(differenceInBytes, sizeof(long long int));
		in_shm.size = differenceInBytes;
		res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
		if (res != TEEC_SUCCESS)
			printf("[NORMAL WORLD] Allocation error with code 0x%x\n", res);
		for (int i = 0; i < differenceInBytes; i++)
		{
			memcpy(((long long int *)in_shm.buffer)+i, startFor+i*sizeof(long long int), sizeof(long long int));
		}


		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE);

		//setting params
		op.params[0].memref.parent = &in_shm;
		op.params[0].memref.size = differenceInBytes;
		op.params[0].memref.offset = 0;
		op.params[1].value.a = differenceInBytes;
		op.params[2].value.a = 1;

	
		res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CHECK_MEMORY_REGION, &op, &err_origin);
		
	
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		TEEC_ReleaseSharedMemory(&in_shm);

		character=getch();
		if (character == 'q')
			break;				
	}
	while (counter >= 0);

	printf("You have %i kWh remaining in your electricity storage!\n", counter);
	printf("Please confirm the demand of %i kWh: ", 20-counter);
    scanf("%i",&amountT);
    printf("Please type in your highest bid in Szabo/kWh: ");
    scanf("%i",&priceT);
    printf("You buy %i kWh for maximal %i Szabo (%i Szabo/kWh).\n", amountT, priceT*amountT, priceT);
	endInput = get_pc();
	differenceInBytes = (endInput - startInput) / sizeof(long long int); //plus einmal für das i 
	in_shm.buffer = calloc(differenceInBytes, sizeof(long long int));
	in_shm.size = differenceInBytes;

	res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
	if (res != TEEC_SUCCESS)
		printf("[NORMAL WORLD] Allocation error with code 0x%x\n", res);

	//fill in the SHḾ
	for (int i = 0; i < differenceInBytes; i++)
	{
		memcpy(((long long int *)in_shm.buffer)+i, startInput+i*sizeof(long long int), sizeof(long long int));
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE);

	//setting params
	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.size = differenceInBytes;
	op.params[0].memref.offset = 0;
	op.params[1].value.a = differenceInBytes;
	op.params[2].value.a = 2;

	
	res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CHECK_MEMORY_REGION, &op, &err_origin);


	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	
	TEEC_ReleaseSharedMemory(&in_shm);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].value.a = amountT;
	op.params[0].value.b = priceT;

	op.params[1].tmpref.buffer = offer;
 	op.params[1].tmpref.size = offer_len;

 	op.params[2].value.a = 1;

 	op.params[3].tmpref.buffer = signature;
 	op.params[3].tmpref.size = signature_len;

	res = TEEC_InvokeCommand(&sess, TA_BLOCKCHAIN_WALLET, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",	res, err_origin);

	offer_output = malloc(offer_len+1);
	sign_output = malloc(signature_len+1);

	snprintf(sign_output, strlen(signature)+1, "%s", signature);
	snprintf(offer_output, strlen(offer)+1, "%s", offer);

	snprintf(command_sub, 194, "mosquitto_sub -h %s -t electricity/%s/# --keysS &", BROKER_IP, device_id);
	
	file = fopen("/bin/pid.txt", "r");
	if (file == NULL)
	{
		printf("Error opening file!\n");
	}

	fscanf(file, "%i", &pid);

	fclose(file);

	sub_is_running = kill(pid, 0);

	if (sub_is_running != 0) 
	{
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
	}

	sprintf(command_send_demand, "mosquitto_pub -h %s -t electricity/%s/demand -m %s%s --keysP", BROKER_IP, device_id, offer_output, sign_output);
	printf("send demand to marketplace\n");
	system(command_send_demand);
	
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

int getch(void) {
      int c=0;

      struct termios org_opts, new_opts;
      int res=0;
          //-----  store old settings -----------
      res=tcgetattr(STDIN_FILENO, &org_opts);
      assert(res==0);
          //---- set new terminal parms --------
      memcpy(&new_opts, &org_opts, sizeof(new_opts));
      new_opts.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL | ECHOPRT | ECHOKE | ICRNL);
      tcsetattr(STDIN_FILENO, TCSANOW, &new_opts);
      c=getchar();
          //------  restore old settings ---------
      res=tcsetattr(STDIN_FILENO, TCSANOW, &org_opts);
      assert(res==0);
      return(c);
}
