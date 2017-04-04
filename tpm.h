#define EFI_TPM_GUID {0xf541796d, 0xa62e, 0x4954, {0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd }};
#define EFI_TPM2_GUID {0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }};

/* Command return codes */
#define TPM_BASE 0x0
#define TPM_SUCCESS TPM_BASE
#define TPM_AUTHFAIL (TPM_BASE + 0x1)
#define TPM_BADINDEX (TPM_BASE + 0x2)

#define TPM_TAG_RQU_COMMAND 0x00C1

EFI_STATUS TPM_readpcr( const UINT8 index, UINT8* result);

EFI_STATUS tpm_log_event(const UINT8 *buf, UINTN size, UINT8 pcr,
			 const CHAR8 *description);

typedef struct {
  uint8_t Major;
  uint8_t Minor;
  uint8_t RevMajor;
  uint8_t RevMinor;
} TCG_VERSION;

typedef struct _TCG_EFI_BOOT_SERVICE_CAPABILITY {
  uint8_t          Size;                /// Size of this structure.
  TCG_VERSION    StructureVersion;
  TCG_VERSION    ProtocolSpecVersion;
  uint8_t          HashAlgorithmBitmap; /// Hash algorithms .
  char        TPMPresentFlag;      /// 00h = TPM not present.
  char        TPMDeactivatedFlag;  /// 01h = TPM currently deactivated.
} TCG_EFI_BOOT_SERVICE_CAPABILITY;

typedef struct _TCG_PCR_EVENT {
  uint32_t PCRIndex;
  uint32_t EventType;
  uint8_t digest[20];
  uint32_t EventSize;
  uint8_t  Event[1];
} TCG_PCR_EVENT;

struct efi_tpm_protocol
{
  EFI_STATUS (EFIAPI *status_check) (struct efi_tpm_protocol *this,
				     TCG_EFI_BOOT_SERVICE_CAPABILITY *ProtocolCapability,
				     uint32_t *TCGFeatureFlags,
				     EFI_PHYSICAL_ADDRESS *EventLogLocation,
				     EFI_PHYSICAL_ADDRESS *EventLogLastEntry);
  EFI_STATUS (EFIAPI *hash_all) (struct efi_tpm_protocol *this,
				 uint8_t *HashData,
				 uint64_t HashLen,
				 uint32_t AlgorithmId,
				 uint64_t *HashedDataLen,
				 uint8_t **HashedDataResult);
  EFI_STATUS (EFIAPI *log_event) (struct efi_tpm_protocol *this,
				  TCG_PCR_EVENT *TCGLogData,
				  uint32_t *EventNumber,
				  uint32_t Flags);
  EFI_STATUS (EFIAPI *pass_through_to_tpm) (struct efi_tpm_protocol *this,
					    uint32_t TpmInputParameterBlockSize,
					    uint8_t *TpmInputParameterBlock,
					    uint32_t TpmOutputParameterBlockSize,
					    uint8_t *TpmOutputParameterBlock);
  EFI_STATUS (EFIAPI *log_extend_event) (struct efi_tpm_protocol *this,
					 EFI_PHYSICAL_ADDRESS HashData,
					 uint64_t HashDataLen,
					 uint32_t AlgorithmId,
					 TCG_PCR_EVENT *TCGLogData,
					 uint32_t *EventNumber,
					 EFI_PHYSICAL_ADDRESS *EventLogLastEntry);
};

typedef struct efi_tpm_protocol efi_tpm_protocol_t;

typedef uint32_t EFI_TCG2_EVENT_LOG_BITMAP;
typedef uint32_t EFI_TCG2_EVENT_LOG_FORMAT;
typedef uint32_t EFI_TCG2_EVENT_ALGORITHM_BITMAP;

typedef struct tdEFI_TCG2_VERSION {
  uint8_t Major;
  uint8_t Minor;
} __attribute__ ((packed)) EFI_TCG2_VERSION;

typedef struct tdEFI_TCG2_BOOT_SERVICE_CAPABILITY_1_0 {
  uint8_t Size;
  EFI_TCG2_VERSION StructureVersion;
  EFI_TCG2_VERSION ProtocolVersion;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP HashAlgorithmBitmap;
  EFI_TCG2_EVENT_LOG_BITMAP SupportedEventLogs;
  BOOLEAN TPMPresentFlag;
  uint16_t MaxCommandSize;
  uint16_t MaxResponseSize;
  uint32_t ManufacturerID;
  uint32_t NumberOfPcrBanks;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP ActivePcrBanks;
} EFI_TCG2_BOOT_SERVICE_CAPABILITY_1_0;

typedef struct tdEFI_TCG2_BOOT_SERVICE_CAPABILITY {
  uint8_t Size;
  EFI_TCG2_VERSION StructureVersion;
  EFI_TCG2_VERSION ProtocolVersion;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP HashAlgorithmBitmap;
  EFI_TCG2_EVENT_LOG_BITMAP SupportedEventLogs;
  BOOLEAN TPMPresentFlag;
  uint16_t MaxCommandSize;
  uint16_t MaxResponseSize;
  uint32_t ManufacturerID;
  uint32_t NumberOfPcrBanks;
  EFI_TCG2_EVENT_ALGORITHM_BITMAP ActivePcrBanks;
} __attribute__ ((packed))  EFI_TCG2_BOOT_SERVICE_CAPABILITY;

typedef uint32_t TCG_PCRINDEX;
typedef uint32_t TCG_EVENTTYPE;

typedef struct tdEFI_TCG2_EVENT_HEADER {
  uint32_t HeaderSize;
  uint16_t HeaderVersion;
  TCG_PCRINDEX PCRIndex;
  TCG_EVENTTYPE EventType;
} __attribute__ ((packed)) EFI_TCG2_EVENT_HEADER;

typedef struct tdEFI_TCG2_EVENT {
  uint32_t Size;
  EFI_TCG2_EVENT_HEADER Header;
  uint8_t Event[1];
} __attribute__ ((packed)) EFI_TCG2_EVENT;

typedef struct{
	uint16_t IPBLength;
	uint16_t Reserved1;
	uint16_t OPBLength;
	uint16_t Reserved2;
	uint8_t TPMOperandIn[1];
}PassThroughToTPM_InputParamBlock;

typedef struct {
	uint16_t OPBLength;
	uint16_t Reserved;
	uint8_t TPMOperandOut[1];
}PassThroughToTPM_OutputParamBlock;

typedef struct {
	uint16_t tag;
	uint32_t paramSize;
	uint32_t ordinal;
	uint32_t pcrIndex;
}PCRReadIncoming;

typedef struct {
	uint16_t tag;
	uint32_t paramSize;
	uint32_t returnCode;
	uint8_t pcr_value[20];
}PCRReadOutgoing;

struct efi_tpm2_protocol
{
  EFI_STATUS (EFIAPI *get_capability) (struct efi_tpm2_protocol *this,
				       EFI_TCG2_BOOT_SERVICE_CAPABILITY *ProtocolCapability);
  EFI_STATUS (EFIAPI *get_event_log) (struct efi_tpm2_protocol *this,
				      EFI_TCG2_EVENT_LOG_FORMAT EventLogFormat,
				      EFI_PHYSICAL_ADDRESS *EventLogLocation,
				      EFI_PHYSICAL_ADDRESS *EventLogLastEntry,
				      BOOLEAN *EventLogTruncated);
  EFI_STATUS (EFIAPI *hash_log_extend_event) (struct efi_tpm2_protocol *this,
					      uint64_t Flags,
					      EFI_PHYSICAL_ADDRESS DataToHash,
					      uint64_t DataToHashLen,
					      EFI_TCG2_EVENT *EfiTcgEvent);
  EFI_STATUS (EFIAPI *submit_command) (struct efi_tpm2_protocol *this,
				       uint32_t InputParameterBlockSize,
				       uint8_t *InputParameterBlock,
				       uint32_t OutputParameterBlockSize,
				       uint8_t *OutputParameterBlock);
  EFI_STATUS (EFIAPI *get_active_pcr_blanks) (struct efi_tpm2_protocol *this,
					      uint32_t *ActivePcrBanks);
  EFI_STATUS (EFIAPI *set_active_pcr_banks) (struct efi_tpm2_protocol *this,
					     uint32_t ActivePcrBanks);
  EFI_STATUS (EFIAPI *get_result_of_set_active_pcr_banks) (struct efi_tpm2_protocol *this,
							   uint32_t *OperationPresent,
							   uint32_t *Response);
};

typedef struct efi_tpm2_protocol efi_tpm2_protocol_t;

static inline char* TPM_memcpy ( void* dest, const void *src, uint32_t n)
{
	char * d = (char*) dest;
	const char *s= (const char *) src;
	if(d<s)
		while (n--)
			*d++ = *s++;
	else 
	{
		d +=n;
		s +=n;

		while (n--)
			*--d = *--s;
	}
	return dest;
}

