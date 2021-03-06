#include <efilib.h>

#define EFI_TPM_GUID {0xf541796d, 0xa62e, 0x4954, {0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd }};
#define EFI_TPM2_GUID {0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }};

#define TPM_ALG_SHA 0x00000004
#define EV_IPL      0x0000000d

EFI_STATUS tpm_log_event(EFI_PHYSICAL_ADDRESS buf, UINTN size, UINT8 pcr,
			  CHAR8 *description);
EFI_STATUS fallback_should_prefer_reset(void);

EFI_STATUS tpm_log_pe(EFI_PHYSICAL_ADDRESS buf, UINTN size, UINT8 *sha1hash,
		      UINT8 pcr);

EFI_STATUS tpm_measure_variable(CHAR16 *dbname, EFI_GUID guid, UINTN size, void *data);

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

typedef struct _EFI_IMAGE_LOAD_EVENT {
  EFI_PHYSICAL_ADDRESS ImageLocationInMemory;
  UINTN ImageLengthInMemory;
  UINTN ImageLinkTimeAddress;
  UINTN LengthOfDevicePath;
  EFI_DEVICE_PATH DevicePath[1];
} EFI_IMAGE_LOAD_EVENT;

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

typedef uint32_t TREE_EVENT_LOG_BITMAP;

typedef uint32_t EFI_TCG2_EVENT_LOG_BITMAP;
typedef uint32_t EFI_TCG2_EVENT_LOG_FORMAT;
typedef uint32_t EFI_TCG2_EVENT_ALGORITHM_BITMAP;

typedef struct tdTREE_VERSION {
  uint8_t Major;
  uint8_t Minor;
} TREE_VERSION;

typedef struct tdEFI_TCG2_VERSION {
  uint8_t Major;
  uint8_t Minor;
} EFI_TCG2_VERSION;

typedef struct tdTREE_BOOT_SERVICE_CAPABILITY {
  uint8_t Size;
  TREE_VERSION StructureVersion;
  TREE_VERSION ProtocolVersion;
  uint32_t HashAlgorithmBitmap;
  TREE_EVENT_LOG_BITMAP SupportedEventLogs;
  BOOLEAN TrEEPresentFlag;
  uint16_t MaxCommandSize;
  uint16_t MaxResponseSize;
  uint32_t ManufacturerID;
} TREE_BOOT_SERVICE_CAPABILITY;

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
} EFI_TCG2_BOOT_SERVICE_CAPABILITY;

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

#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_1_2 0x00000001
#define EFI_TCG2_EVENT_LOG_FORMAT_TCG_2   0x00000002

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

typedef UINT32                     TCG_EVENTTYPE;

#define EV_EFI_EVENT_BASE                   ((TCG_EVENTTYPE) 0x80000000)
#define EV_EFI_VARIABLE_DRIVER_CONFIG       (EV_EFI_EVENT_BASE + 1)
#define EV_EFI_VARIABLE_BOOT                (EV_EFI_EVENT_BASE + 2)
#define EV_EFI_BOOT_SERVICES_APPLICATION    (EV_EFI_EVENT_BASE + 3)
#define EV_EFI_BOOT_SERVICES_DRIVER         (EV_EFI_EVENT_BASE + 4)
#define EV_EFI_RUNTIME_SERVICES_DRIVER      (EV_EFI_EVENT_BASE + 5)
#define EV_EFI_GPT_EVENT                    (EV_EFI_EVENT_BASE + 6)
#define EV_EFI_ACTION                       (EV_EFI_EVENT_BASE + 7)
#define EV_EFI_PLATFORM_FIRMWARE_BLOB       (EV_EFI_EVENT_BASE + 8)
#define EV_EFI_HANDOFF_TABLES               (EV_EFI_EVENT_BASE + 9)
#define EV_EFI_VARIABLE_AUTHORITY           (EV_EFI_EVENT_BASE + 0xE0)

#define PE_COFF_IMAGE 0x0000000000000010
#define MAX_PCR_INDEX 23


// TO READ PCR
typedef struct {
	uint16_t tag;
	uint32_t paramSize;
	uint32_t ordinal;
	uint32_t pcrIndex;
} __attribute__ ((packed)) tpm_PCRReadIncoming;

typedef struct {
	uint16_t tag;
	uint32_t paramSize;
	uint32_t returnCode;
	uint8_t pcr_value[20];
} __attribute__ ((packed)) tpm_PCRReadOutgoing;

typedef struct {
	uint16_t tag;
	uint32_t paramSize;
	uint32_t returnCode;
} __attribute__ ((packed)) tpm_PCRReadOutgoing_hdr;

//TPM2

 // Table 205 - Defines for SHA1 Hash Values
#define SHA1_DIGEST_SIZE 20
#define SHA1_BLOCK_SIZE  64
	    
// Table 206 - Defines for SHA256 Hash Value
#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64
		        
// Table 207 - Defines for SHA384 Hash Values
#define SHA384_DIGEST_SIZE 48
#define SHA384_BLOCK_SIZE  128
				    
// Table 208 - Defines for SHA512 Hash Values
#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128
					        
// Table 209 - Defines for SM3_256 Hash Values
#define SM3_256_DIGEST_SIZE 32
#define SM3_256_BLOCK_SIZE  64

typedef UINT16 TPM_ALG_ID;
typedef TPM_ALG_ID TPMI_ALG_HASH;
#define TPM_ALG_SHA1           (TPM_ALG_ID)(0x0004)
#define TPM_ALG_SHA256         (TPM_ALG_ID)(0x000B)

typedef UINT16 TPM_ST;
#define TPM_ST_NO_SESSIONS          (TPM_ST)(0x8001)

typedef UINT32 TPM_CC;
#define TPM_CC_PCR_Read                   (TPM_CC)(0x0000017E)

typedef UINT32 TPM_RC;
#define TPM_RC_SUCCESS           (TPM_RC)(0x000)

#define IMPLEMENTATION_PCR 24
#define PCR_SELECT_MAX ((IMPLEMENTATION_PCR + 7) / 8)
typedef UINT8 BYTE;
//typedef UINT8 BOOL;

#define HASH_COUNT 5

typedef struct {
	TPM_ST tag;
	UINT32 paramSize;
	TPM_CC commandCode;
}__attribute__ ((packed)) TPM2_COMMAND_HEADER;

typedef struct {
	TPM_ST tag;
	UINT32 paramSize;
	TPM_RC responseCode;
}__attribute__ ((packed)) TPM2_RESPONSE_HEADER;

typedef struct {
	TPMI_ALG_HASH hash;
	UINT8 sizeofSelect;
	BYTE pcrSelect[PCR_SELECT_MAX];
}TPMS_PCR_SELECTION;

typedef struct {
	UINT32 count;
	TPMS_PCR_SELECTION pcrSelections[HASH_COUNT];
}TPML_PCR_SELECTION;

typedef union {
	BYTE sha1[SHA1_DIGEST_SIZE];
	BYTE sha256[SHA256_DIGEST_SIZE];
	BYTE sm3_256[SM3_256_DIGEST_SIZE];
	BYTE sha384[SHA384_DIGEST_SIZE];
	BYTE sha512[SHA512_DIGEST_SIZE];
}TPMU_HA;

typedef struct {
	TPMI_ALG_HASH hashAlg;
	TPMU_HA       digest;
}TPMT_HA;

typedef struct {
	UINT16 size;
	BYTE buffer[sizeof(TPMU_HA)];
}TPM2B_DIGEST;

typedef struct {
	UINT16 size;
	BYTE buffer[sizeof(TPMT_HA)];
}TPM2B_DATA;

typedef struct {
	UINT32 count;
	TPM2B_DIGEST digests[8];
}TPML_DIGEST;

// prototypes
EFI_STATUS Tpm2PcrRead ( TPML_PCR_SELECTION *, UINT32 *, TPML_PCR_SELECTION  *, TPML_DIGEST *);

void tpm_itochar(UINT8* input, CHAR16* output, uint32_t length);

EFI_STATUS TPM_readPCR(UINT32 pcrIndex, UINT8 *pcrval);
//EFI_STATUS TPM_readPCR( const UINT32 index, UINT8* result);
