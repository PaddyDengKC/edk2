#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <Uefi.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseLib.h>

#define TWO_BYTE_ENCODE  0x82

/**
  Retrieves the size, in bytes, of the context buffer required for hash operations.

  If this interface is not supported, then return zero.

  @return  The size, in bytes, of the context buffer required for hash operations.
  @retval  0   This interface is not supported.

**/
typedef
UINTN
(EFIAPI *EFI_HASH_GET_CONTEXT_SIZE)(
  VOID
  );

/**
  Initializes user-supplied memory pointed by Sha1Context as hash context for
  subsequent use.

  If HashContext is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[out]  HashContext  Pointer to Hashcontext being initialized.

  @retval TRUE   Hash context initialization succeeded.
  @retval FALSE  Hash context initialization failed.
  @retval FALSE  This interface is not supported.

**/
typedef
BOOLEAN
(EFIAPI *EFI_HASH_INIT)(
  OUT  VOID  *HashContext
  );

/**
  Digests the input data and updates Hash context.

  This function performs Hash digest on a data buffer of the specified size.
  It can be called multiple times to compute the digest of long or discontinuous data streams.
  Hash context should be already correctly initialized by HashInit(), and should not be finalized
  by HashFinal(). Behavior with invalid context is undefined.

  If HashContext is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  HashContext  Pointer to the Hash context.
  @param[in]       Data         Pointer to the buffer containing the data to be hashed.
  @param[in]       DataSize     Size of Data buffer in bytes.

  @retval TRUE   SHA-1 data digest succeeded.
  @retval FALSE  SHA-1 data digest failed.
  @retval FALSE  This interface is not supported.

**/
typedef
BOOLEAN
(EFIAPI *EFI_HASH_UPDATE)(
  IN OUT  VOID        *HashContext,
  IN      CONST VOID  *Data,
  IN      UINTN       DataSize
  );

/**
  Completes computation of the Hash digest value.

  This function completes hash computation and retrieves the digest value into
  the specified memory. After this function has been called, the Hash context cannot
  be used again.
  Hash context should be already correctly initialized by HashInit(), and should not be
  finalized by HashFinal(). Behavior with invalid Hash context is undefined.

  If HashContext is NULL, then return FALSE.
  If HashValue is NULL, then return FALSE.
  If this interface is not supported, then return FALSE.

  @param[in, out]  HashContext  Pointer to the Hash context.
  @param[out]      HashValue    Pointer to a buffer that receives the Hash digest
                                value.

  @retval TRUE   Hash digest computation succeeded.
  @retval FALSE  Hash digest computation failed.
  @retval FALSE  This interface is not supported.

**/
typedef
BOOLEAN
(EFIAPI *EFI_HASH_FINAL)(
  IN OUT  VOID   *HashContext,
  OUT     UINT8  *HashValue
  );

typedef struct {
  UINT32                       HashSize;
  EFI_HASH_GET_CONTEXT_SIZE    GetContextSize;
  EFI_HASH_INIT                Init;
  EFI_HASH_UPDATE              Update;
  EFI_HASH_FINAL               Final;
  VOID                         **HashShaCtx;
  UINT8                        *OidValue;
  UINTN                        OidLength;
} EFI_HASH_INFO;

void print_buf(uint8_t *buf, size_t size);

errno_t read_file_to_buf(char *filename, uint8_t **buf, size_t *buf_size);

UINT8
FindHashAlgorithmIndex (
  IN     UINT8   *SigData,
  IN     UINT32  SigDataSize
  );