#include "CheckDb.h"

void print_cert_stack(EFI_CERT_STACK *cert_stack);
void print_signer_info(UINT8 *pkcs7, UINTN pkcs7_size);
void print_cert_info(UINT8 *cert, UINTN cert_size);
void signed_data_self_verify(
  UINT8* signed_data,
  UINTN signed_data_size,
  UINT8* data,
  UINTN data_size
);
//
// Hash context pointer
//
VOID  *mHashSha256Ctx = NULL;
VOID  *mHashSha384Ctx = NULL;
VOID  *mHashSha512Ctx = NULL;

UINT8  mSha256OidValue[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
UINT8  mSha384OidValue[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
UINT8  mSha512OidValue[] = { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

EFI_HASH_INFO  mHashInfo[] = {
  { SHA256_DIGEST_SIZE, Sha256GetContextSize, Sha256Init, Sha256Update, Sha256Final, &mHashSha256Ctx, mSha256OidValue, 9 },
  { SHA384_DIGEST_SIZE, Sha384GetContextSize, Sha384Init, Sha384Update, Sha384Final, &mHashSha384Ctx, mSha384OidValue, 9 },
  { SHA512_DIGEST_SIZE, Sha512GetContextSize, Sha512Init, Sha512Update, Sha512Final, &mHashSha512Ctx, mSha512OidValue, 9 },
};

int
main (
  int   argc,
  char  *argv[]
  )
{
  errno_t err = 0;
  UINT8 *db_buf = NULL;
  UINTN db_size = 0;
  EFI_VARIABLE_AUTHENTICATION_2 *var_auth = NULL;
  UINTN db_cert_data_size = 0;
  UINT8* db_cert_data = NULL;
  UINT8 *trusted_cert = NULL;
  UINTN trusted_cert_size = 0;
  UINT8 *kek_buf = NULL;
  UINTN kek_size = 0;
  EFI_SIGNATURE_LIST *cert_list = NULL;
  EFI_SIGNATURE_DATA             *cert;
  UINTN                          idx;
  UINTN                          cert_count;
  UINT8 *hashed_data = NULL;
  UINT8 *data_pointer = NULL;
  UINTN hashed_data_size = 0;
  CHAR16* variable_name = L"dbx";
  UINTN copy_length;
  UINT32 var_attr = 0x67;
  UINT8 *payload = NULL;
  UINTN payload_size = 0;
  BOOLEAN verify_result;

  err = read_file_to_buf("DBX_U\\DBXUpdate.bin", &db_buf, &db_size);
  if (err != 0) {
    goto Exit;
  }
  var_auth = (EFI_VARIABLE_AUTHENTICATION_2*)db_buf;

  db_cert_data_size = (size_t)var_auth->AuthInfo.Hdr.dwLength - OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  db_cert_data = (uint8_t*)(&var_auth->AuthInfo.CertData[0]);
  printf("hash alg = %d\n", FindHashAlgorithmIndex(db_cert_data, (UINT32)db_cert_data_size));
  print_signer_info(db_cert_data, db_cert_data_size);
  payload  = db_cert_data + db_cert_data_size;
  payload_size = db_size - ((OFFSET_OF (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo)) +
  (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData))) - (UINTN)db_cert_data_size;

  hashed_data_size = payload_size + sizeof (EFI_TIME) + sizeof (UINT32) +
  sizeof (EFI_GUID) + StrSize (variable_name) - sizeof (CHAR16);
  hashed_data = malloc(hashed_data_size);
  if (hashed_data == NULL) {
    err = 1;
    printf("Unable to allocate memory for hash data");
    goto Exit;
  }
  
  data_pointer = hashed_data;
  copy_length = StrLen (variable_name) * sizeof (CHAR16);
  CopyMem (data_pointer, variable_name, copy_length);
  data_pointer += copy_length;

  copy_length = sizeof (EFI_GUID);
  CopyMem (data_pointer, &gEfiImageSecurityDatabaseGuid, copy_length);
  data_pointer += copy_length;

  copy_length = sizeof (UINT32);
  CopyMem (data_pointer, &var_attr, copy_length);
  data_pointer += copy_length;

  copy_length = sizeof (EFI_TIME);
  CopyMem (data_pointer, &var_auth->TimeStamp, copy_length);
  data_pointer += copy_length;

  CopyMem (data_pointer, payload, payload_size);

//   {
//     FILE *stream;
//     fopen_s(&stream, "new_data.bin", "wb");
//     fwrite(hashed_data, hashed_data_size, 1, stream);
//     fclose(stream);
//   }

  err = read_file_to_buf("KEK", &kek_buf, &kek_size);
  if (err != 0) {
    goto Exit;
  }
  var_auth = (EFI_VARIABLE_AUTHENTICATION_2*)kek_buf;
  if (CompareGuid((void*)&gEfiCertPkcs7Guid, (void*)&(var_auth->AuthInfo.CertType))) {
    printf("kek has a auth header\n");
    cert_list = (EFI_SIGNATURE_LIST*)(kek_buf + sizeof(EFI_TIME) + var_auth->AuthInfo.Hdr.dwLength);
  } else {
    printf("kek doesn't has a auth header\n");
    cert_list = (EFI_SIGNATURE_LIST*)kek_buf;
  }

  while ((UINTN)cert_list - (UINTN)kek_buf < kek_size) {
    if (CompareGuid (&cert_list->SignatureType, &gEfiCertX509Guid)) {
      printf("testing\n");
      cert      = (EFI_SIGNATURE_DATA *)((UINT8 *)cert_list + sizeof (EFI_SIGNATURE_LIST) + cert_list->SignatureHeaderSize);
      cert_count = (cert_list->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - cert_list->SignatureHeaderSize) / cert_list->SignatureSize;
      for (idx = 0; idx < cert_count; idx++) {
        //
        // Iterate each Signature Data Node within this CertList for a verify
        //
        trusted_cert     = cert->SignatureData;
        trusted_cert_size = cert_list->SignatureSize - (sizeof (EFI_SIGNATURE_DATA) - 1);

        //
        // Verify Pkcs7 SignedData via Pkcs7Verify library.
        //
        verify_result = Pkcs7Verify (
                         db_cert_data,
                         db_cert_data_size,
                         trusted_cert,
                         trusted_cert_size,
                         hashed_data,
                         hashed_data_size
                         );
        printf("verify_result = %d\n", verify_result);
        if (verify_result) {
          err = 0;
          printf("verify passed\n");
          goto Exit;
        }

        cert = (EFI_SIGNATURE_DATA *)((UINT8 *)cert + cert_list->SignatureSize);
      }
    }

    cert_list     = (EFI_SIGNATURE_LIST *)((UINT8 *)cert_list + cert_list->SignatureListSize);
  }
  err = 1;
  printf("Not able to find a matching cert\n");
  signed_data_self_verify(db_cert_data, db_cert_data_size, hashed_data, hashed_data_size);
//   read_file_to_buf("toplevel.crt", &trusted_cert, &trusted_cert_size);
//   verify_result = Pkcs7Verify (
//     db_cert_data,
//     db_cert_data_size,
//     trusted_cert,
//     trusted_cert_size,
//     hashed_data,
//     hashed_data_size
//     );
// printf("verify_result = %d\n", verify_result);
// free(trusted_cert);
// read_file_to_buf("Microsoft Corporation KEK CA 2011.crt", &trusted_cert, &trusted_cert_size);
// verify_result = Pkcs7Verify (
//   db_cert_data,
//   db_cert_data_size,
//   trusted_cert,
//   trusted_cert_size,
//   hashed_data,
//   hashed_data_size
//   );
// printf("verify_result = %d\n", verify_result);

Exit:
  if (db_buf != NULL) {
    free(db_buf);
  }
  if (kek_buf != NULL) {
    free(db_buf);
  }
  if (hashed_data != NULL) {
    free(hashed_data);
  }
  return err;
}

void print_buf(uint8_t *buf, size_t size) {
  size_t idx;

  for (idx = 0; idx < size; idx += 1) {
    if (idx % 16 == 15) {
      printf("%02X\n", *(buf + idx));
    } else {
      printf("%02X ", *(buf + idx));
    }
  }
  if (idx % 16 != 15) {
    printf("\n");
  } 
}

errno_t read_file_to_buf(char *filename, uint8_t **buf, size_t *filesize) {
  FILE *stream = NULL;
  long filesize_loc;
  size_t read_size;
  void *file_buf = NULL;
  errno_t err = 0;

  err = fopen_s(&stream, filename,"rb" );
  if (err != 0) {
    printf("Open file %s failed\n", filename);
    goto Exit;
  }
  fseek(stream, 0L, SEEK_END);
  filesize_loc = ftell(stream);
  file_buf = malloc((size_t)filesize_loc);
  if (file_buf == 0) {
    printf("Allocate buffer to read %s failed\n", filename);
    err = 1;
    goto Exit;
  }

  fseek(stream, 0L, SEEK_SET);
  read_size = fread_s((void*)file_buf, filesize_loc, 1, filesize_loc, stream);
  if (read_size != filesize_loc) {
    printf("Not able to read the entire file. err = %d\n", ferror(stream));
    err = 1;
    goto Exit;
  }
  *buf = file_buf;
  *filesize = (size_t)filesize_loc;
  fclose(stream);
  return 0;

Exit:
  if (stream != NULL) {
    fclose(stream);
  }
  if (file_buf != NULL) {
    free(file_buf);
  }
return err;
}

/**
  Find hash algorithm index.

  @param[in]  SigData      Pointer to the PKCS#7 message.
  @param[in]  SigDataSize  Length of the PKCS#7 message.

  @retval UINT8        Hash Algorithm Index.
**/
UINT8
FindHashAlgorithmIndex (
  IN     UINT8   *SigData,
  IN     UINT32  SigDataSize
  )
{
  UINT8  i;

  for (i = 0; i < (sizeof (mHashInfo) / sizeof (EFI_HASH_INFO)); i++) {
    if (  (  (SigDataSize >= (13 + mHashInfo[i].OidLength))
          && (  ((*(SigData + 1) & TWO_BYTE_ENCODE) == TWO_BYTE_ENCODE)
             && (CompareMem (SigData + 13, mHashInfo[i].OidValue, mHashInfo[i].OidLength) == 0)))
       || (  ((SigDataSize >= (32 +  mHashInfo[i].OidLength)))
          && (  ((*(SigData + 20) & TWO_BYTE_ENCODE) == TWO_BYTE_ENCODE)
             && (CompareMem (SigData + 32, mHashInfo[i].OidValue, mHashInfo[i].OidLength) == 0))))
    {
      break;
    }
  }

  return i;
}

void print_signer_info(UINT8 *pkcs7, UINTN pkcs7_size) {
  UINT8                          *top_level_cert = NULL;
  UINTN                          top_level_cert_size = 0;
  UINT8                          *signer_stack = NULL;
  UINTN                          signer_stack_size = 0;
  BOOLEAN verify_status = FALSE;


  verify_status = Pkcs7GetSigners (
    pkcs7,
    pkcs7_size,
    &signer_stack,
    &signer_stack_size,
    &top_level_cert,
    &top_level_cert_size
    );
    if (!verify_status) {
      printf("Not able to get signer info\n");
      goto Exit;
    }
    printf("signer_stack_size = %lld\n", signer_stack_size);
    printf("Print signer stack:\n");
    print_cert_stack((EFI_CERT_STACK*)signer_stack);
  
    printf("top_level_cert_size = %lld\n", top_level_cert_size);
    printf("Print top level signer:\n");
    //print_cert_stack((EFI_CERT_STACK*)top_level_cert);
    print_cert_info(top_level_cert, top_level_cert_size);

Exit:
    if (top_level_cert != NULL) {
      Pkcs7FreeSigners(top_level_cert);
    }
    if (signer_stack != NULL) {
      Pkcs7FreeSigners(signer_stack);
    }
}

void print_cert_stack(EFI_CERT_STACK *cert_stack) {
  EFI_CERT_DATA *cert_data = (EFI_CERT_DATA*)((UINT8*)cert_stack + sizeof(UINT8));
  UINTN idx;

  printf("Got %d certs in the stack\n", cert_stack->CertNumber);
  for (idx = 0; idx < (UINTN)cert_stack->CertNumber; idx += 1) {
    print_cert_info(cert_data->CertDataBuffer, cert_data->CertDataLength);
    cert_data = (EFI_CERT_DATA*)((UINT8*)cert_data + cert_data->CertDataLength + 4);
  }
}


#define SUBJECT_NAME_SIZE 250
void print_cert_info(UINT8 *cert, UINTN cert_size) {
  CHAR8 subject_name[SUBJECT_NAME_SIZE +  5];
  UINTN subject_name_size = SUBJECT_NAME_SIZE;
  EFI_STATUS success;

  subject_name_size = SUBJECT_NAME_SIZE;
  success = X509GetCommonName(cert, cert_size, subject_name, &subject_name_size);
  if (EFI_ERROR(success)) {
    printf("Not able to get subject name\n");
    return;
  } else {
    printf("%s\n", subject_name);
    {
      errno_t err;
      FILE *stream = NULL;
      err = fopen_s(&stream, subject_name, "wb");
      if (err) {
        printf("Not able to write %s\n", subject_name);
      } else {
        fwrite(cert, cert_size, 1, stream);
      }
      if (stream != NULL) {
        fclose(stream);
        stream = NULL;
      }
    }
  }
}

void signed_data_self_verify(
  UINT8* signed_data,
  UINTN signed_data_size,
  UINT8* data,
  UINTN data_size
) {
  UINT8                          *top_level_cert = NULL;
  UINTN                          top_level_cert_size = 0;
  EFI_CERT_STACK                 *signer_stack = NULL;
  UINTN                          signer_stack_size = 0;
  BOOLEAN verify_status = FALSE;
  EFI_CERT_DATA *cert_data = NULL;
  UINTN idx;


  verify_status = Pkcs7GetSigners (
    signed_data,
    signed_data_size,
    (UINT8**)&signer_stack,
    &signer_stack_size,
    &top_level_cert,
    &top_level_cert_size
    );
    if (!verify_status) {
      printf("Not able to get signer info\n");
      goto Exit;
    }
    printf("top_level_cert_size = %lld\n", top_level_cert_size);
    printf("Print top level signer:\n");
    print_cert_info(top_level_cert, top_level_cert_size);

    verify_status = Pkcs7Verify (
      signed_data,
      signed_data_size,
      top_level_cert,
      top_level_cert_size,
      data,
      data_size
    );
    printf("Signed data self verify with top level cert: %d\n", verify_status);

  
    printf("Got %d certs in the stack\n", signer_stack->CertNumber);
    cert_data =  (EFI_CERT_DATA*)((UINT8*)signer_stack + sizeof(UINT8));
    for (idx = 0; idx < (UINTN)signer_stack->CertNumber; idx += 1) {
      verify_status = Pkcs7Verify (
        signed_data,
        signed_data_size,
        top_level_cert,
        top_level_cert_size,
        data,
        data_size
      );
      printf("Signed data self verify with %lld signer: %d\n", idx, verify_status);
        cert_data = (EFI_CERT_DATA*)((UINT8*)cert_data + cert_data->CertDataLength + 4);
    }
  
Exit:
    if (top_level_cert != NULL) {
      Pkcs7FreeSigners(top_level_cert);
    }
    if (signer_stack != NULL) {
      Pkcs7FreeSigners((UINT8*)signer_stack);
    }
}