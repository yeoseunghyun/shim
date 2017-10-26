#include <efi.h>
#include <efilib.h>
#include <string.h>
#include <stdint.h>

#include "console.h"
#include "tpm.h"

extern UINT8 in_protocol;

#define perror(fmt, ...) ({                                             \
			UINTN __perror_ret = 0;                               \
			if (!in_protocol)                                     \
				__perror_ret = Print((fmt), ##__VA_ARGS__);   \
			__perror_ret;                                         \
		})


typedef struct {
	CHAR16 *VariableName;
	EFI_GUID *VendorGuid;
	VOID *Data;
	UINTN Size;
} VARIABLE_RECORD;

UINTN measuredcount = 0;
VARIABLE_RECORD *measureddata = NULL;

EFI_GUID tpm_guid = EFI_TPM_GUID;
EFI_GUID tpm2_guid = EFI_TPM2_GUID;

static efi_tpm2_protocol_t *tpm2;
static efi_tpm_protocol_t *tpm;
CHAR16 TPM_itoa64[16]=
L"0123456789ABCDEF";
void tpm_itochar(UINT8* input, CHAR16* output, uint32_t length){
console_notify(L"in tpm_itochar\n");

	int i=0;
	int len = length;
	UINT8 tmp =0;
	UINT8 a,b;

	int c =0;
	for(i=0;i<len;i++){
		tmp=input[i];
		a = tmp & 0xf0;
		a = a >> 4;
		b = tmp & 0x0f;
		output[c++]= TPM_itoa64[a];
		output[c++] = TPM_itoa64[b];
	}
}



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

static EFI_STATUS tpm2_get_caps(efi_tpm2_protocol_t *tpm,
				EFI_TCG2_BOOT_SERVICE_CAPABILITY *caps,
				BOOLEAN *old_caps)
{
	EFI_STATUS status;

	caps->Size = (UINT8)sizeof(*caps);

	status = uefi_call_wrapper(tpm->get_capability, 2, tpm, caps);

	if (status != EFI_SUCCESS)
		return status;

	if (caps->StructureVersion.Major == 1 &&
	    caps->StructureVersion.Minor == 0)
		*old_caps = TRUE;

	return EFI_SUCCESS;
}

static BOOLEAN tpm2_present(EFI_TCG2_BOOT_SERVICE_CAPABILITY *caps,
			    BOOLEAN old_caps)
{
	TREE_BOOT_SERVICE_CAPABILITY *caps_1_0;

	if (old_caps) {
		caps_1_0 = (TREE_BOOT_SERVICE_CAPABILITY *)caps;
		if (caps_1_0->TrEEPresentFlag)
			return TRUE;
	}

	if (caps->TPMPresentFlag)
		return TRUE;

	return FALSE;
}

static inline EFI_TCG2_EVENT_LOG_BITMAP
tpm2_get_supported_logs(efi_tpm2_protocol_t *tpm,
			EFI_TCG2_BOOT_SERVICE_CAPABILITY *caps,
			BOOLEAN old_caps)
{
	if (old_caps)
		return ((TREE_BOOT_SERVICE_CAPABILITY *)caps)->SupportedEventLogs;

	return caps->SupportedEventLogs;
}

/*
 * According to TCG EFI Protocol Specification for TPM 2.0 family,
 * all events generated after the invocation of EFI_TCG2_GET_EVENT_LOG
 * shall be stored in an instance of an EFI_CONFIGURATION_TABLE aka
 * EFI TCG 2.0 final events table. Hence, it is necessary to trigger the
 * internal switch through calling get_event_log() in order to allow
 * to retrieve the logs from OS runtime.
 */
static EFI_STATUS trigger_tcg2_final_events_table(efi_tpm2_protocol_t *tpm2,
						  EFI_TCG2_EVENT_LOG_BITMAP supported_logs)
{
	EFI_TCG2_EVENT_LOG_FORMAT log_fmt;
	EFI_PHYSICAL_ADDRESS start;
	EFI_PHYSICAL_ADDRESS end;
	BOOLEAN truncated;

	if (supported_logs & EFI_TCG2_EVENT_LOG_FORMAT_TCG_2)
		log_fmt = EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;
	else
		log_fmt = EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2;

	return uefi_call_wrapper(tpm2->get_event_log, 5, tpm2, log_fmt,
				 &start, &end, &truncated);
}

static EFI_STATUS tpm_locate_protocol(efi_tpm_protocol_t **tpm,
				      efi_tpm2_protocol_t **tpm2,
				      BOOLEAN *old_caps_p,
				      EFI_TCG2_BOOT_SERVICE_CAPABILITY *capsp)
{
	EFI_STATUS status;

	*tpm = NULL;
	*tpm2 = NULL;
	status = LibLocateProtocol(&tpm2_guid, (VOID **)tpm2);
	/* TPM 2.0 */
	if (status == EFI_SUCCESS) {
		BOOLEAN old_caps;
		EFI_TCG2_BOOT_SERVICE_CAPABILITY caps;

		status = tpm2_get_caps(*tpm2, &caps, &old_caps);
		if (EFI_ERROR(status))
			return status;

		if (tpm2_present(&caps, old_caps)) {
			if (old_caps_p)
				*old_caps_p = old_caps;
			if (capsp)
				memcpy(capsp, &caps, sizeof(caps));
			return EFI_SUCCESS;
		}
	} else {
		status = LibLocateProtocol(&tpm_guid, (VOID **)tpm);
		if (EFI_ERROR(status))
			return status;

		if (tpm_present(*tpm))
			return EFI_SUCCESS;
	}

	return EFI_NOT_FOUND;
}

static EFI_STATUS tpm_log_event_raw(EFI_PHYSICAL_ADDRESS buf, UINTN size,
				    UINT8 pcr, const CHAR8 *log, UINTN logsize,
				    UINT32 type, CHAR8 *hash)
{
	EFI_STATUS status;
	efi_tpm_protocol_t *tpm;
	efi_tpm2_protocol_t *tpm2;
	BOOLEAN old_caps;
	EFI_TCG2_BOOT_SERVICE_CAPABILITY caps;

	status = tpm_locate_protocol(&tpm, &tpm2, &old_caps, &caps);
	if (EFI_ERROR(status)) {
		return status;
	} else if (tpm2) {
		EFI_TCG2_EVENT *event;
		EFI_TCG2_EVENT_LOG_BITMAP supported_logs;

		supported_logs = tpm2_get_supported_logs(tpm2, &caps, old_caps);

		status = trigger_tcg2_final_events_table(tpm2, supported_logs);
		if (EFI_ERROR(status)) {
			perror(L"Unable to trigger tcg2 final events table: %r\n", status);
			return status;
		}

		event = AllocatePool(sizeof(*event) + logsize);
		if (!event) {
			perror(L"Unable to allocate event structure\n");
			return EFI_OUT_OF_RESOURCES;
		}

		event->Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER);
		event->Header.HeaderVersion = 1;
		event->Header.PCRIndex = pcr;
		event->Header.EventType = type;
		event->Size = sizeof(*event) - sizeof(event->Event) + logsize + 1;
		CopyMem(event->Event, (VOID *)log, logsize);
		if (hash) {
			/* TPM 2 systems will generate the appropriate hash
			   themselves if we pass PE_COFF_IMAGE
			*/
			status = uefi_call_wrapper(tpm2->hash_log_extend_event,
						   5, tpm2, PE_COFF_IMAGE, buf,
						   (UINT64) size, event);
		} else {
			status = uefi_call_wrapper(tpm2->hash_log_extend_event,
						   5, tpm2, 0, buf,
						   (UINT64) size, event);
		}
		FreePool(event);
		return status;
	} else if (tpm) {
		TCG_PCR_EVENT *event;
		UINT32 eventnum = 0;
		EFI_PHYSICAL_ADDRESS lastevent;

		status = LibLocateProtocol(&tpm_guid, (VOID **)&tpm);

		if (status != EFI_SUCCESS)
			return EFI_SUCCESS;

		if (!tpm_present(tpm))
			return EFI_SUCCESS;

		event = AllocatePool(sizeof(*event) + logsize);

		if (!event) {
			perror(L"Unable to allocate event structure\n");
			return EFI_OUT_OF_RESOURCES;
		}

		event->PCRIndex = pcr;
		event->EventType = type;
		event->EventSize = logsize;
		CopyMem(event->Event, (VOID *)log, logsize);
		if (hash) {
			/* TPM 1.2 devices require us to pass the Authenticode
			   hash rather than allowing the firmware to attempt
			   to calculate it */
			CopyMem(event->digest, hash, sizeof(event->digest));
			status = uefi_call_wrapper(tpm->log_extend_event, 7,
						   tpm, 0, 0, TPM_ALG_SHA,
						   event, &eventnum,
						   &lastevent);
		} else {
			status = uefi_call_wrapper(tpm->log_extend_event, 7,
						   tpm, buf, (UINT64)size,
						   TPM_ALG_SHA, event,
						   &eventnum, &lastevent);
		}
		FreePool(event);
		return status;
	}

	return EFI_SUCCESS;
}

EFI_STATUS tpm_log_event(EFI_PHYSICAL_ADDRESS buf, UINTN size, UINT8 pcr,
			 const CHAR8 *description)
{
	return tpm_log_event_raw(buf, size, pcr, description,
				 strlen(description) + 1, 0xd, NULL);
}

EFI_STATUS tpm_log_pe(EFI_PHYSICAL_ADDRESS buf, UINTN size, UINT8 *sha1hash,
		      UINT8 pcr)
{
	EFI_IMAGE_LOAD_EVENT ImageLoad;

	// All of this is informational and forces us to do more parsing before
	// we can generate it, so let's just leave it out for now
	ImageLoad.ImageLocationInMemory = 0;
	ImageLoad.ImageLengthInMemory = 0;
	ImageLoad.ImageLinkTimeAddress = 0;
	ImageLoad.LengthOfDevicePath = 0;

	return tpm_log_event_raw(buf, size, pcr, (CHAR8 *)&ImageLoad,
				 sizeof(ImageLoad),
				 EV_EFI_BOOT_SERVICES_APPLICATION, sha1hash);
}

typedef struct {
	EFI_GUID VariableName;
	UINT64 UnicodeNameLength;
	UINT64 VariableDataLength;
	CHAR16 UnicodeName[1];
	INT8 VariableData[1];
} EFI_VARIABLE_DATA_TREE;

static BOOLEAN tpm_data_measured(CHAR16 *VarName, EFI_GUID VendorGuid, UINTN VarSize, VOID *VarData)
{
	UINTN i;

	for (i=0; i<measuredcount; i++) {
		if ((StrCmp (VarName, measureddata[i].VariableName) == 0) &&
		    (CompareGuid (&VendorGuid, measureddata[i].VendorGuid)) &&
		    (VarSize == measureddata[i].Size) &&
		    (CompareMem (VarData, measureddata[i].Data, VarSize) == 0)) {
			return TRUE;
		}
	}

	return FALSE;
}

static EFI_STATUS tpm_record_data_measurement(CHAR16 *VarName, EFI_GUID VendorGuid, UINTN VarSize, VOID *VarData)
{
	if (measureddata == NULL) {
		measureddata = AllocatePool(sizeof(*measureddata));
	} else {
		measureddata = ReallocatePool(measureddata, measuredcount * sizeof(*measureddata),
					      (measuredcount + 1) * sizeof(*measureddata));
	}

	if (measureddata == NULL)
		return EFI_OUT_OF_RESOURCES;

	measureddata[measuredcount].VariableName = AllocatePool(StrSize(VarName));
	measureddata[measuredcount].VendorGuid = AllocatePool(sizeof(EFI_GUID));
	measureddata[measuredcount].Data = AllocatePool(VarSize);

	if (measureddata[measuredcount].VariableName == NULL ||
	    measureddata[measuredcount].VendorGuid == NULL ||
	    measureddata[measuredcount].Data == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	StrCpy(measureddata[measuredcount].VariableName, VarName);
	CopyMem(measureddata[measuredcount].VendorGuid, &VendorGuid, sizeof(EFI_GUID));
	CopyMem(measureddata[measuredcount].Data, VarData, VarSize);
	measureddata[measuredcount].Size = VarSize;
	measuredcount++;

	return EFI_SUCCESS;
}

EFI_STATUS tpm_measure_variable(CHAR16 *VarName, EFI_GUID VendorGuid, UINTN VarSize, VOID *VarData)
{
	EFI_STATUS Status;
	UINTN VarNameLength;
	EFI_VARIABLE_DATA_TREE *VarLog;
	UINT32 VarLogSize;

	/* Don't measure something that we've already measured */
	if (tpm_data_measured(VarName, VendorGuid, VarSize, VarData))
		return EFI_SUCCESS;

	VarNameLength = StrLen (VarName);
	VarLogSize = (UINT32)(sizeof (*VarLog) +
			      VarNameLength * sizeof (*VarName) +
			      VarSize -
			      sizeof (VarLog->UnicodeName) -
			      sizeof (VarLog->VariableData));

	VarLog = (EFI_VARIABLE_DATA_TREE *) AllocateZeroPool (VarLogSize);
	if (VarLog == NULL) {
		return EFI_OUT_OF_RESOURCES;
	}

	CopyMem (&VarLog->VariableName, &VendorGuid,
		 sizeof(VarLog->VariableName));
	VarLog->UnicodeNameLength  = VarNameLength;
	VarLog->VariableDataLength = VarSize;
	CopyMem (VarLog->UnicodeName, VarName,
		 VarNameLength * sizeof (*VarName));
	CopyMem ((CHAR16 *)VarLog->UnicodeName + VarNameLength, VarData,
		 VarSize);

	Status = tpm_log_event_raw((EFI_PHYSICAL_ADDRESS)(intptr_t)VarLog,
				   VarLogSize, 7, (CHAR8 *)VarLog, VarLogSize,
				   EV_EFI_VARIABLE_AUTHORITY, NULL);

	FreePool(VarLog);

	if (Status != EFI_SUCCESS)
		return Status;

	return tpm_record_data_measurement(VarName, VendorGuid, VarSize,
					   VarData);
}

///READ PCR///
#define MAX_PCR 24

typedef struct {
	UINT64 count;
	TPML_DIGEST pcr_values[MAX_PCR];
} tpm2_pcrs;

typedef struct {
	TPML_PCR_SELECTION pcr_selections;
	tpm2_pcrs pcrs;
} pcr_context;


#pragma pack(1)
typedef struct {
	TPM2_COMMAND_HEADER Header;
	TPML_PCR_SELECTION PcrSelectionIn;
}TPM2_PCR_READ_COMMAND;

typedef struct {
	TPM2_RESPONSE_HEADER Header;
	uint32_t PcrUpdateCounter;
	TPML_PCR_SELECTION PcrSelectionOut;
	TPML_DIGEST PcrValues;
}TPM2_PCR_READ_RESPONSE;
#pragma pack()

static uint16_t Swap_Bytes16(UINT16 x){
	return ((x<<8)|(x>>8));
}
static uint32_t Swap_Bytes32(UINT32 x){
	UINT32 lb;
	UINT32 hb;

	lb= (UINT32)Swap_Bytes16((UINT16)(x & 0xffff));
	hb= (UINT32)Swap_Bytes16((UINT16)(x >> 16));

	return (lb<<16|hb);
}



VOID 
Set_PcrSelect_Bit( TPMS_PCR_SELECTION *s, 
                   UINT32 pcr) 
{
    s->pcrSelect[((pcr) / 8)] |= (1 << ((pcr) % 8));
}


VOID 
Clear_PcrSelect_Bits( TPMS_PCR_SELECTION *s)
{
    s->pcrSelect[0] = 0;
    s->pcrSelect[1] = 0;
    s->pcrSelect[2] = 0;
}


VOID 
Set_PcrSelect_Size( TPMS_PCR_SELECTION *s, 
                    UINT8 size) 
{
    s->sizeofSelect = size;
}


BOOLEAN
Is_PcrSelect_Bit_Set( TPMS_PCR_SELECTION *s, 
                      UINT32 pcr) 
{
    return (s->pcrSelect[((pcr) / 8)] & (1 << ((pcr) % 8)));
}


BOOLEAN
Unset_PcrSections(TPML_PCR_SELECTION *s) 
{
    UINT32 i, j;

    for (i = 0; i < s->count; i++) {
        for (j = 0; j < s->pcrSelections[i].sizeofSelect; j++) {
            if (s->pcrSelections[i].pcrSelect[j]) {
                return FALSE;
            }
        }
    }

    return TRUE;
}


VOID 
Update_Pcr_Selections( TPML_PCR_SELECTION *s1, 
                       TPML_PCR_SELECTION *s2)
{
    UINT32 i, j, k;

    for (j = 0; j < s2->count; j++) {
        for (i = 0; i < s1->count; i++) {
            if (s2->pcrSelections[j].hash != s1->pcrSelections[i].hash) {
                continue;
            }

            for (k = 0; k < s1->pcrSelections[i].sizeofSelect; k++) {
                s1->pcrSelections[i].pcrSelect[k] &= ~s2->pcrSelections[j].pcrSelect[k];
            }
        }
    }
}


VOID
Show_Pcr_Values( pcr_context *context) 
{
	console_notify(L"in  Show_Pcr_Values \n");
    UINT32 vi = 0, di = 0, i, pcr_id, k;
    UINT8 result[36];
    CHAR16 pcr_msg[73];
    memset(pcr_msg,0,sizeof(pcr_msg));
    memset(result,0,sizeof(result));

    for (i = 0; i < context->pcr_selections.count; i++) {

        //Print(L"\nBank (Algorithm): sha256_only (0x%04x)\n\n",
          //      context->pcr_selections.pcrSelections[i].hash);

        for ( pcr_id = 0; pcr_id < MAX_PCR; pcr_id++) {
		if (pcr_id == 7){
            if (!Is_PcrSelect_Bit_Set(&context->pcr_selections.pcrSelections[i], pcr_id)) {
                continue;
            }
            
            if (vi >= context->pcrs.count || di >= context->pcrs.pcr_values[vi].count) {
            //    Print(L"ERROR: Trying to output PCR values but nothing more to output\n");
                return;
            }

           // Print(L"[%02d] ", pcr_id);
            for (k = 0; k < context->pcrs.pcr_values[vi].digests[di].size; k++)
               result[k] = context -> pcrs.pcr_values[vi].digests[di].buffer[k];
		   // Print(L" %02x", context->pcrs.pcr_values[vi].digests[di].buffer[k]);
    //        Print(L"\n");

           
	    if (++di < context->pcrs.pcr_values[vi].count) {
                continue;
            }

            di = 0;
            if (++vi < context->pcrs.count) {
                continue;
            }
        }
  //      Print(L"\n");
    }
    }

    tpm_itochar(result,pcr_msg,36);
    console_notify (pcr_msg);
    console_notify (L" PCR READ DONE\n");
}


BOOLEAN 
Read_Pcr_Values( pcr_context *context)
{
	console_notify(L"in Read_Pcr_Values\n");
    TPML_PCR_SELECTION pcr_selection_tmp;
    TPML_PCR_SELECTION pcr_selection_out;
    UINT32 pcr_update_counter;
    EFI_STATUS Status;
 
    CopyMem(&pcr_selection_tmp, &context->pcr_selections, sizeof(pcr_selection_tmp));

    context->pcrs.count = 0;
    do {
        Status = Tpm2PcrRead( &pcr_selection_tmp, 
                              &pcr_update_counter,
                              &pcr_selection_out,
                              &context->pcrs.pcr_values[context->pcrs.count]);
        if (EFI_ERROR (Status)) {
        console_notify(L"in Read_Pcr_Values: error 1\n");    //Print(L"ERROR: Tpm2PcrRead failed [%d]\n", Status);
            return FALSE;
        }

        // unmask pcrSelectionOut bits from pcrSelectionIn
        Update_Pcr_Selections(&pcr_selection_tmp, &pcr_selection_out);

        // goto step 2 if pcrSelctionIn still has bits set
    } while (++context->pcrs.count < MAX_PCR && !Unset_PcrSections(&pcr_selection_tmp));

    // hack - this needs to be re-worked
    if (context->pcrs.count >= MAX_PCR && !Unset_PcrSections(&pcr_selection_tmp)) {
      console_notify(L"in Read_Pcr_Values: error 2\n"); 
	    //Print(L"ERROR: Reading PCRs. Too much PCRs found [%d]\n", context->pcrs.count);
        return FALSE;
    }

    return TRUE;
}


//
// Modified from original UDK2015 SecurityPkg routine
//
EFI_STATUS
Tpm2PcrRead( TPML_PCR_SELECTION  *PcrSelectionIn,
             UINT32              *PcrUpdateCounter,
             TPML_PCR_SELECTION  *PcrSelectionOut,
             TPML_DIGEST         *PcrValues)
{
    EFI_STATUS             Status;
    TPM2_PCR_READ_COMMAND  SendBuffer;
    TPM2_PCR_READ_RESPONSE RecvBuffer;
    UINT32                 SendBufferSize;
    UINT32                 RecvBufferSize;
    UINTN                  Index;
    TPML_DIGEST            *PcrValuesOut;
    TPM2B_DIGEST           *Digests;
    
    // Construct the TPM2 command
    SendBuffer.Header.tag = Swap_Bytes16(TPM_ST_NO_SESSIONS);
    SendBuffer.Header.commandCode = Swap_Bytes32(TPM_CC_PCR_Read);
    SendBuffer.PcrSelectionIn.count = Swap_Bytes32(PcrSelectionIn->count);
    for (Index = 0; Index < PcrSelectionIn->count; Index++) {
        SendBuffer.PcrSelectionIn.pcrSelections[Index].hash = 
            Swap_Bytes16(PcrSelectionIn->pcrSelections[Index].hash);
        SendBuffer.PcrSelectionIn.pcrSelections[Index].sizeofSelect = 
            PcrSelectionIn->pcrSelections[Index].sizeofSelect;
        CopyMem (&SendBuffer.PcrSelectionIn.pcrSelections[Index].pcrSelect, 
            &PcrSelectionIn->pcrSelections[Index].pcrSelect, 
            SendBuffer.PcrSelectionIn.pcrSelections[Index].sizeofSelect);
    }
    SendBufferSize = sizeof(SendBuffer.Header) + sizeof(SendBuffer.PcrSelectionIn.count) + 
        sizeof(SendBuffer.PcrSelectionIn.pcrSelections[0]) * PcrSelectionIn->count;
    SendBuffer.Header.paramSize = Swap_Bytes32 (SendBufferSize);

    RecvBufferSize = sizeof (RecvBuffer);
   
    Status = uefi_call_wrapper(tpm2->submit_command,5, tpm2,
                                          SendBufferSize,
                                          (UINT8 *)&SendBuffer,
                                          RecvBufferSize,
                                          (UINT8 *)&RecvBuffer);
    if (EFI_ERROR (Status)) {
        console_notify(L"ERROR: SubmitCommand failed [%d]\n");//, Status);
        return Status;
    }

    if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER)) {
        console_notify(L"ERROR: RecvBufferSize [%x]\n");//, RecvBufferSize);
        return EFI_DEVICE_ERROR;
    }

    if (Swap_Bytes32(RecvBuffer.Header.responseCode) != TPM_RC_SUCCESS) {
		uint32_t test = Swap_Bytes32(RecvBuffer.Header.responseCode);
		test = test & 0x0000FFFF;
		test = Swap_Bytes32(test);

		CHAR16 buf_test[20];
		memset(buf_test,0,sizeof(buf_test));

		uint8_t *ptr_test = (uint8_t *)&test;
		tpm_itochar(ptr_test,buf_test,sizeof(test));

		console_notify(L"ERROR Tpm2 ResponseCode [%x]\n");//, Swap_Bytes32(RecvBuffer.Header.responseCode));
		console_notify(buf_test);
		return EFI_NOT_FOUND;
    }


    // Response - PcrUpdateCounter
    if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER) + sizeof(RecvBuffer.PcrUpdateCounter)) {
        console_notify(L"Tpm2PcrRead - RecvBufferSize Error - %x\n");//, RecvBufferSize);
        return EFI_DEVICE_ERROR;
    }
    *PcrUpdateCounter = Swap_Bytes32(RecvBuffer.PcrUpdateCounter);

    // Response - PcrSelectionOut
    if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER) + sizeof(RecvBuffer.PcrUpdateCounter) +
        sizeof(RecvBuffer.PcrSelectionOut.count)) {
        console_notify(L"Tpm2PcrRead - RecvBufferSize Error - %x\n");//, RecvBufferSize);
        return EFI_DEVICE_ERROR;
    }
    PcrSelectionOut->count = Swap_Bytes32(RecvBuffer.PcrSelectionOut.count);

    if (RecvBufferSize < sizeof (TPM2_RESPONSE_HEADER) + sizeof(RecvBuffer.PcrUpdateCounter) 
        + sizeof(RecvBuffer.PcrSelectionOut.count)
        + sizeof(RecvBuffer.PcrSelectionOut.pcrSelections[0]) * PcrSelectionOut->count) {
        console_notify(L"Tpm2PcrRead - RecvBufferSize Error - %x\n");//, RecvBufferSize);
        return EFI_DEVICE_ERROR;
    }

    for (Index = 0; Index < PcrSelectionOut->count; Index++) {
        PcrSelectionOut->pcrSelections[Index].hash = 
            Swap_Bytes16(RecvBuffer.PcrSelectionOut.pcrSelections[Index].hash);
        PcrSelectionOut->pcrSelections[Index].sizeofSelect = 
            RecvBuffer.PcrSelectionOut.pcrSelections[Index].sizeofSelect;
        CopyMem (&PcrSelectionOut->pcrSelections[Index].pcrSelect, 
                 &RecvBuffer.PcrSelectionOut.pcrSelections[Index].pcrSelect, 
                 PcrSelectionOut->pcrSelections[Index].sizeofSelect);
    }


    // Response - return digests in PcrValue
    PcrValuesOut = (TPML_DIGEST *)((UINT8 *)&RecvBuffer + sizeof (TPM2_RESPONSE_HEADER) 
                   + sizeof(RecvBuffer.PcrUpdateCounter) + sizeof(RecvBuffer.PcrSelectionOut.count)
                   + sizeof(RecvBuffer.PcrSelectionOut.pcrSelections[0]) * PcrSelectionOut->count);
    PcrValues->count = Swap_Bytes32(PcrValuesOut->count);
    Digests = PcrValuesOut->digests;
    for (Index = 0; Index < PcrValues->count; Index++) {
        PcrValues->digests[Index].size = Swap_Bytes16(Digests->size);
        CopyMem (&PcrValues->digests[Index].buffer, &Digests->buffer, 
                 PcrValues->digests[Index].size);
        Digests = (TPM2B_DIGEST *)((UINT8 *)Digests + sizeof(Digests->size) 
                  + PcrValues->digests[Index].size);
    }

    return EFI_SUCCESS;
}


static void 
Init_Pcr_Selection( pcr_context *context, 
                  TPMI_ALG_HASH alg)
{
    TPML_PCR_SELECTION *s = (TPML_PCR_SELECTION *) &(context->pcr_selections);

    s->count = 1;
    s->pcrSelections[0].hash = alg;
    Set_PcrSelect_Size(&s->pcrSelections[0], 3);
    Clear_PcrSelect_Bits(&s->pcrSelections[0]);

    UINT32 pcr_id;
    for (pcr_id = 0; pcr_id < MAX_PCR; pcr_id++) {
        Set_PcrSelect_Bit(&s->pcrSelections[0], pcr_id);
    }
}



EFI_STATUS 
TPM_readPCR()
//TPM_readPCR(uint32_t index, uint8_t *buf)
{
    EFI_STATUS Status;
    BOOLEAN old_caps;
    EFI_TCG2_BOOT_SERVICE_CAPABILITY caps;
    
    pcr_context context;

console_notify(L"in TPM_READ PCR\n");

    Status = tpm_locate_protocol(&tpm, &tpm2, &old_caps, &caps);
    
    if (EFI_ERROR (Status)) {
        return Status;
    }

  //  Init_Pcr_Selection(&context,TPM_ALG_SHA);
    Init_Pcr_Selection(&context,TPM_ALG_SHA256);
    if (Read_Pcr_Values(&context))
        Show_Pcr_Values(&context);

    return Status;
}
