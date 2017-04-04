#include <efi.h>
#include <efilib.h>
#include <string.h>

#include "tpm.h"

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

#define swap_bytes32(x) ((((x) & 0xff) << 24) | (((x) & 0xff00) << 8) | (((x) & 0xff0000) >> 8) | (((x) & 0xff000000UL) >> 24))
#define swap_bytes16(x) ((((x) & 0xff) << 8) | (((x) & 0xff00) >> 8))

EFI_STATUS TPM_passTroughToTPM (const PassThroughToTPM_InputParamBlock* input, PassThroughToTPM_OutputParamBlock* output)
{
	efi_tpm_protocol_t *tpm = NULL;
	EFI_STATUS status;

	uint32_t inhdrsize = sizeof(*input)-sizeof(input->TPMOperandIn);
	uint32_t outhdrsize = sizeof(*output)-sizeof(output->TPMOperandOut);

	if(!input){
		perror(L"Unable to locate result\n");
		return EFI_OUT_OF_RESOURCES;
	}
	if(!output){
		perror(L"Unable to locate result\n");
		return EFI_OUT_OF_RESOURCES;
	}

	status = LibLocateProtocol(&tpm_guid, (VOID **)&tpm);

	if(status == EFI_SUCCESS){
		perror(L"PassThroughToTPM: TPM LCATE FAIL\n");
		return EFI_NOT_FOUND;
	}


	status = uefi_call_wrapper(tpm->pass_through_to_tpm, 5, tpm, input-> IPBLength - inhdrsize, (uint8_t *)input-> TPMOperandIn, input-> OPBLength-outhdrsize, output-> TPMOperandOut);	
	switch(status){
		case EFI_SUCCESS:
 			return EFI_SUCCESS;
		case EFI_DEVICE_ERROR:	
			perror(L"PassthroughtoTPM: command failed\n");
			return status;
		case EFI_BUFFER_TOO_SMALL:
			perror(L"PassthroughtoTPM: Output buffer too small\n");
			return status;
		case EFI_NOT_FOUND:
			perror(L"PassthroughtoTPM: TPM unavailable\n");
			return status;
		case EFI_INVALID_PARAMETER:
			perror(L"PassthroughtoTPM: Invalid parameter\n");
			return status;
		default:
			perror(L"PassthroughtoTPM: UNKNOWN ERROR\n");
			return status;
	}
}

EFI_STATUS TPM_readpcr( const UINT8 index, UINT8* result ) 
{

	if(!result){
		perror(L"Unable to locate result\n");
		return  EFI_OUT_OF_RESOURCES;
	}

	PassThroughToTPM_InputParamBlock *passThroughInput = NULL;
	PCRReadIncoming *pcrReadIncoming = NULL;
	PCRReadIncoming Incoming;
	uint16_t inputlen = sizeof( *passThroughInput ) - sizeof( passThroughInput->TPMOperandIn ) + sizeof( *pcrReadIncoming );

	PassThroughToTPM_OutputParamBlock *passThroughOutput = NULL;
	PCRReadOutgoing* pcrReadOutgoing = NULL;
	uint16_t outputlen = sizeof( *passThroughOutput ) - sizeof( passThroughOutput->TPMOperandOut ) + sizeof( *pcrReadOutgoing );

	passThroughInput = AllocatePool( inputlen );
	if( !passThroughInput ) {
		perror(L"readpcr: memory allocation failed" );
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
	 //CONVERT
	uint32_t tmp = swap_bytes16(0x00C1);
		
	pcrReadIncoming->tag = tmp;
	tmp = swap_bytes32( sizeof( *pcrReadIncoming ) );
	pcrReadIncoming->paramSize = tmp;
	tmp = swap_bytes32( 0x00000015 );
	pcrReadIncoming->ordinal = tmp;
	tmp = swap_bytes32( (UINT32) index);
	pcrReadIncoming->pcrIndex = tmp;

	pcrReadIncoming = (PCRReadIncoming *)&(passThroughInput->TPMOperandIn[0]);
	TPM_memcpy(pcrReadIncoming, &Incoming, sizeof(Incoming));

	passThroughOutput = AllocatePool( outputlen );
	if( ! passThroughOutput ) {
		perror(L"readpcr: memory allocation failed");
		return EFI_OUT_OF_RESOURCES;
	}
//////////////////////////////////////////////////////////////////////////////////////
	TPM_passTroughToTPM( passThroughInput, passThroughOutput );
	free( passThroughInput );

	pcrReadOutgoing = (void *)passThroughOutput->TPMOperandOut;
	uint32_t tpm_PCRreadReturnCode = swap_bytes32( pcrReadOutgoing->returnCode );

	if( tpm_PCRreadReturnCode != TPM_SUCCESS ) {
		free( passThroughOutput );

		if( tpm_PCRreadReturnCode == TPM_BADINDEX ) {
			perror(L"readpcr: bad pcr index" );
		}

        perror( L"readpcr: tpm_PCRreadReturnCode:e" );
	}

	TPM_memcpy( result, pcrReadOutgoing->pcr_value,20 );
	free( passThroughOutput );
	return EFI_SUCCESS;
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
