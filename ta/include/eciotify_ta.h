/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TA_ECIOTIFY_H
#define TA_ECIOTIFY_H

/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_ECIOTIFY_UUID { 0x8aaaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

#define BROKER_IP "dev.weeve.network"


/***********************************************/
/***********************************************/
#define TA_GEN_MQTTS_KEYS						1
#define TA_GEN_TESTIMONY_KEYS					2
#define TA_GEN_WALLET_KEYS						3
#define TA_REGISTER_DEVICE						4
#define TA_SAVE_BC_KEYS							5
/***********************************************/		
/***********************************************/
#define TA_HELLO_WORLD_CHECK_MEMORY_REGION 		6
#define TA_BLOCKCHAIN_WALLET					7
/***********************************************/
/***********************************************/
#define TA_HELLO_WORLD_CMD_OBJ_ECDSA			8
#define TA_HELLO_WORLD_CMD_OBJ_ECDH				9
#define TA_HELLO_WORLD_CMD_OBJ_GET_SIGN_KEYS 	10
#define TA_HELLO_WORLD_CMD_OBJ_ENCRYPT			11
#define TA_HELLO_WORLD_CMD_OBJ_DECRYPT			12
#define TA_HELLO_WORLD_CMD_CREATE_CREDENTIAL 	13
#define TA_HELLO_WORLD_CMD_GET_ECDSA_KEYS	 	14
#define TA_HELLO_WORLD_CMD_GET_ECDH_KEYS		15
#define TA_HELLO_WORLD_CMD_OBJ_SIGN_KEYS 		16
#define TA_HELLO_WORLD_CMD_VERIFY_SIGN			17
#define TA_HELLO_WORLD_CMD_DERIVE_KEY			18
#define TA_HELLO_WORLD_CMD_DELETE_PERS_OBJ		19
#define TA_GET_DEVICE_ID						20
/***********************************************/
#define	TA_DEL_KEYS								21
/***********************************************/
#define TA_SAVE_MARKETPLACE_KEY					22
/*
 * Supported algorithms
 */
#define TA_SHA_SHA1	0

#endif /*TA_ECIOTIFY_H*/
