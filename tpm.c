#include <efi.h>
#include <efilib.h>
#include <string.h>
#include "console.h"
#include "tpm.h"


static unsigned char TPM_itoa64[16] =
"0123456789ABCDEF";
static void itochar(UINT8* input, CHAR16* output){
	int i =20;
	UINT8 tmp =0;
	UINT8 a,b;
	UINT8 c =0;
	for(i=0;i<20;i++){
		tmp=input[i];
		a=tmp>>4;
		a = a & 0xf;
		output[c++]=TPM_itoa64[a];
		b= tmp & 0xf;
		output[c++]=TPM_itoa64[b];
	}
}

static const uint32_t TPM_ORD_PcrRead = 0x00000015;

extern UINT8 in_protocol;

#define perror(fmt, ...) ({                                             \
			UINTN __perror_ret = 0;                               \
			if (!in_protocol)                                     \
				__perror_ret = Print((fmt), ##__VA_ARGS__);   \
			__perror_ret;                                         \
		})

EFI_GUID tpm_guid = EFI_TPM_GUID;
EFI_GUID tpm2_guid = EFI_TPM2_GUID;

static BOOLEAN tpm_present(efi_tpm_protocol_t *tpm)
{
	EFI_STATUS status;
	TCG_EFI_BOOT_SERVICE_CAPABILITY caps;
	UINT32 flags;
	EFI_PHYSICAL_ADDRESS eventlog, lastevent;

	caps.Size = (UINT8)sizeof(caps);
	status = uefi_call_wrapper(tpm->status_check, 5, tpm, &caps, &flags,
				   &eventlog, &lastevent);

	if (status != EFI_SUCCESS || caps.TPMDeactivatedFlag
	    || !caps.TPMPresentFlag)
		return FALSE;

	return TRUE;
}

static BOOLEAN tpm2_present(efi_tpm2_protocol_t *tpm)
{
	EFI_STATUS status;
	EFI_TCG2_BOOT_SERVICE_CAPABILITY caps;
	EFI_TCG2_BOOT_SERVICE_CAPABILITY_1_0 *caps_1_0;

	caps.Size = (UINT8)sizeof(caps);

	status = uefi_call_wrapper(tpm->get_capability, 2, tpm, &caps);

	if (status != EFI_SUCCESS)
		return FALSE;

	if (caps.StructureVersion.Major == 1 &&
	    caps.StructureVersion.Minor == 0) {
		caps_1_0 = (EFI_TCG2_BOOT_SERVICE_CAPABILITY_1_0 *)&caps;
		if (caps_1_0->TPMPresentFlag)
			return TRUE;
	} else {
		if (caps.TPMPresentFlag)
			return TRUE;
	}

	return FALSE;
}


static uint16_t swap_bytes16(UINT16 x)
{
	return ((x<<8)|(x>>8));
}


static uint32_t swap_bytes32(UINT32 x){
	UINT32 lb;
	UINT32 ub;

	lb= (UINT32)swap_bytes16((UINT16)x);
	ub= (UINT32)swap_bytes16((UINT16)x);

	return(lb<<16|ub);
}
/*
EFI_STATUS TPM_passTroughToTPM (PassThroughToTPM_InputParamBlock* input, PassThroughToTPM_OutputParamBlock* output)
{
	efi_tpm_protocol_t *tpm = NULL;
	EFI_STATUS status;

	uint32_t inhdrsize = sizeof(*input)-sizeof(input->TPMOperandIn);
	uint32_t outhdrsize = sizeof(*output)-sizeof(output->TPMOperandOut);

	if(!input){
		console_notify(L"Unable to locate result\n");
		return EFI_OUT_OF_RESOURCES;
	}
	if(!output){
		console_notify(L"Unable to locate result\n");
		return EFI_OUT_OF_RESOURCES;
	}

	status = LibLocateProtocol(&tpm_guid, (VOID **)&tpm);

	if(status != EFI_SUCCESS){
		console_notify(L"ERROR! PassThroughToTPM: TPM LCATE FAIL\n");
		return EFI_NOT_FOUND;
	} if(!tpm_present(tpm)) {
			console_notify(L"ERROR! tpm_present(tpm)\n");
			if (tpm == NULL)
				perror(L"ERROR! tpm == NULL\n");
			return EFI_SUCCESS;
		}
	}

	if( !tpm_present(tpm)){
		console_notify(L"PassThroughToTPM: TPM present fail\n");
		return EFI_NOT_FOUND;
	}

	status = uefi_call_wrapper(tpm->pass_through_to_tpm, 5, tpm, input-> IPBLength - inhdrsize, input-> TPMOperandIn, output-> OPBLength-outhdrsize, output-> TPMOperandOut);	
	switch(status){
		case EFI_SUCCESS:
			console_notify(L"PassthroughtoTPM: EFI_SUCCESS\n");
 			return EFI_SUCCESS;
		case EFI_DEVICE_ERROR:	
			console_notify(L"PassthroughtoTPM: command failed\n");
			return status;
		case EFI_BUFFER_TOO_SMALL:
			console_notify(L"PassthroughtoTPM: Output buffer too small\n");
			return status;
		case EFI_NOT_FOUND:
			console_notify(L"PassthroughtoTPM: TPM unavailable\n");
			return status;
		case EFI_INVALID_PARAMETER:
			console_notify(L"PassthroughtoTPM: Invalid parameter\n");
			return status;
		default:
			console_notify(L"PassthroughtoTPM: UNKNOWN ERROR\n");
			return status;
	}
}
*/
EFI_STATUS TPM_readpcr( const UINT8 index, UINT8* result ) 
{


	efi_tpm_protocol_t *tpm = NULL;
	EFI_STATUS status;

	if(!result){
		console_notify(L"Unable to locate result\n");
		return  EFI_OUT_OF_RESOURCES;
	}
	
	status = LibLocateProtocol(&tpm_guid, (VOID **)&tpm);
	
	if(status != EFI_SUCCESS){
		console_notify(L"PassThroughToTPM: TPM LCATE FAIL\n");
		return EFI_NOT_FOUND;
	}

	if( !tpm_present(tpm)){
		console_notify(L"PassThroughToTPM: TPM present fail\n");
		return EFI_NOT_FOUND;
	}

	PCRReadOutgoing* pcrReadOutgoing = NULL;


/*
	PassThroughToTPM_InputParamBlock *passThroughInput = NULL;
	PCRReadIncoming *pcrReadIncoming = NULL;
	pcrReadIncoming = AllocatePool((uint16_t) sizeof(PCRReadIncoming));
	PCRReadIncoming Incoming;
	uint16_t inputlen = sizeof( *passThroughInput ) - sizeof( passThroughInput->TPMOperandIn ) + sizeof( *pcrReadIncoming );


	PassThroughToTPM_OutputParamBlock *passThroughOutput = NULL;
	uint16_t outputlen = sizeof( *passThroughOutput ) - sizeof( passThroughOutput->TPMOperandOut ) + sizeof( *pcrReadOutgoing );

	passThroughInput = AllocatePool( inputlen );
	if( !passThroughInput ) {
		console_notify(L"readpcr: memory allocation failed\n" );
		return EFI_OUT_OF_RESOURCES;
	}

	passThroughInput->IPBLength = inputlen;
	passThroughInput->OPBLength = outputlen;

	pcrReadIncoming = (PCRReadIncoming *)&(passThroughInput->TPMOperandIn[0]);
	Incoming.tag = TPM_TAG_RQU_COMMAND;
	Incoming.paramSize = sizeof( *pcrReadIncoming );
	Incoming.ordinal = TPM_ORD_PcrRead;
	Incoming.pcrIndex = index;

	pcrReadIncoming = &Incoming;
*/

	UINT8 CmdBuf[64];

	*(UINT16*)&CmdBuf[0] = swap_bytes16(TPM_TAG_RQU_COMMAND);
	*(UINT32*)&CmdBuf[2] = swap_bytes32( sizeof(PCRReadIncoming) );
	*(UINT32*)&CmdBuf[6] = swap_bytes32(TPM_ORD_PcrRead);
	*(UINT32*)&CmdBuf[10]= swap_bytes32(index);

/*	
	pcrReadIncoming->tag = swap_bytes16(TPM_TAG_RQU_COMMAND);
	pcrReadIncoming->paramSize = swap_bytes32( sizeof(PCRReadIncoming) );
	pcrReadIncoming->ordinal = swap_bytes32(TPM_ORD_PcrRead);
	pcrReadIncoming->pcrIndex = swap_bytes32(index);

	pcrReadIncoming = (PCRReadIncoming *)&(passThroughInput->TPMOperandIn[0]);
	TPM_memcpy(pcrReadIncoming, &Incoming, sizeof(Incoming));

	passThroughOutput = AllocatePool( outputlen );
	if( ! passThroughOutput ) {
		console_notify(L"readpcr: memory allocation failedi\n");
		return EFI_OUT_OF_RESOURCES;
	}
	status = TPM_passTroughToTPM( passThroughInput, passThroughOutput );
	free( passThroughInput );
*/

	status = uefi_call_wrapper(tpm->pass_through_to_tpm, 5, tpm, sizeof(PCRReadIncoming), CmdBuf, sizeof(CmdBuf), CmdBuf);

	if( status != EFI_SUCCESS){
		console_notify(L"readpcr: passThrough fail\n");
		return EFI_OUT_OF_RESOURCES;
	}

	pcrReadOutgoing = (PCRReadOutgoing*)&CmdBuf[0];
	
	uint32_t tpm_PCRreadReturnCode = pcrReadOutgoing->returnCode ;

	if( tpm_PCRreadReturnCode != TPM_SUCCESS  || 
			pcrReadOutgoing->tag != swap_bytes16(TPM_TAG_RSP_COMMAND)) {
		//free( passThroughOutput );
		if( tpm_PCRreadReturnCode == TPM_BADINDEX ) {
			console_notify(L"readpcr: bad pcr index\n" );
		}
        console_notify( L"readpcr: tpm_PCRreadReturnCode:e\n" );
	}

	//UINT8 tmp_val[20];
	int valsize = 0;
	for(valsize =0;valsize <20; valsize++){
		result[valsize]=pcrReadOutgoing->pcr_value[valsize];
	}
	//TPM_memcpy( result, pcrReadOutgoing->pcr_value,20 );
	//free( passThroughOutput );


	//result = tmp_val;

	CHAR16 testing[40]={0,};
	CHAR8 testing8[20]={0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,};

	itochar(testing8, testing);
	console_notify(testing);
	memset(testing, 0, sizeof(testing));

	itochar(result, testing);
	console_notify(testing);

	memset(testing, 0, sizeof(testing));
	console_notify(L"end of readpcr\n");

	return status;
}

EFI_STATUS tpm_log_event(const UINT8 *buf, UINTN size, UINT8 pcr,
			 const CHAR8 *description)
{
	EFI_STATUS status;
	efi_tpm_protocol_t *tpm = NULL;
	efi_tpm2_protocol_t *tpm2 = NULL;

	status = LibLocateProtocol(&tpm2_guid, (VOID **)&tpm2);
	/* TPM 2.0 */
	if (status == EFI_SUCCESS) {
		EFI_TCG2_EVENT *event;

		if (!tpm2_present(tpm2))
			return EFI_SUCCESS;

		event = AllocatePool(sizeof(*event) + strlen(description) + 1);
		if (!event) {
			perror(L"Unable to allocate event structure\n");
			return EFI_OUT_OF_RESOURCES;
		}

		event->Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER);
		event->Header.HeaderVersion = 1;
		event->Header.PCRIndex = pcr;
		event->Header.EventType = 0x0d;
		event->Size = sizeof(*event) - sizeof(event->Event) + strlen(description) + 1;
		memcpy(event->Event, description, strlen(description) + 1);
		status = uefi_call_wrapper(tpm2->hash_log_extend_event, 5, tpm2,
					   0, (EFI_PHYSICAL_ADDRESS)buf, (UINT64) size, event);
		FreePool(event);
		return status;
	} else {
		TCG_PCR_EVENT *event;
		UINT32 algorithm, eventnum = 0;
		EFI_PHYSICAL_ADDRESS lastevent;

		status = LibLocateProtocol(&tpm_guid, (VOID **)&tpm);

		if (status != EFI_SUCCESS) {
			perror(L"LibLocateProtocol(tpm_guid)\n");
			return EFI_SUCCESS;
		} if (!tpm_present(tpm)) {
			perror(L"tpm_present(tpm)\n");
			if (tpm == NULL)
				perror(L"tpm == NULL\n");
			return EFI_SUCCESS;
		}

		event = AllocatePool(sizeof(*event) + strlen(description) + 1);
		size = sizeof(*event)+strlen(description)+1;

		if (!event) {
			perror(L"Unable to allocate event structure\n");
			return EFI_OUT_OF_RESOURCES;
		}

		event->PCRIndex = pcr;
		event->EventType = 0x0d;
		event->EventSize = strlen(description) + 1;
		memcpy(event->Event, description, strlen(description) + 1);
		algorithm = 0x00000004;
		status = uefi_call_wrapper(tpm->log_extend_event, 7, tpm, (EFI_PHYSICAL_ADDRESS)buf,
					   (UINT64)size, algorithm, event,
					   &eventnum, &lastevent);
		FreePool(event);
		return status;
	}

	return EFI_SUCCESS;
}
