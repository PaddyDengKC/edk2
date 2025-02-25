#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <Uefi.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseMemoryLib.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseLib.h>

errno_t
read_file_to_buf (
  char     *filename,
  uint8_t  **buf,
  size_t   *filesize
  );

void
print_x509_info (
  UINT8  *cert,
  UINTN  cert_size
  );

int
work (
  CHAR8     *db_filename,
  CHAR8     *key_filename,
  CHAR16    *var_name,
  EFI_GUID  *var_guid,
  UINT32    var_attr
  );

void
print_help (
  )
{
  printf ("CheckDB\n");
  printf ("A tool to check if the given DB / DBX file is signed by the specific KEK / PK\n");
  printf ("CheckDB <db / dbx file> <kek / pk file> <variable name> <vendor guid> <variable attribute>\n\n");

  printf ("Variable name, vendor guid and variable attribute is used to generate the hash for signature verification.\n");
  printf ("It should match the data provided when the DB / DBX is signed and will be used.\n");
  printf ("e.x. CheckDb.exe DBXUpdate.bin KEK.bin dbx d719b2cb-3d3a-4596-a3bc-dad00e67656f 0x67\n\n");

  printf ("Typical guid used for SecureBoot variables:\n");
  printf ("gEfiImageSecurityDatabaseGuid: d719b2cb-3d3a-4596-a3bc-dad00e67656f\n\n");

  printf ("Typical attributes used for SecureBoot variables:\n");
  printf ("0x67: NV | BS | RT | TIME_BASED_AUTH | APPEND\n");
  printf ("0x27: NV | BS | RT | TIME_BASED_AUTH\n");
}

int
main (
  int   argc,
  char  *argv[]
  )
{
  EFI_GUID    var_guid;
  CHAR16      *var_name    = NULL;
  UINTN       var_name_len = 0;
  int         return_val   = 1;
  EFI_STATUS  efi_st;
  UINT64      var_attr64    = 0;
  CHAR8       *var_attr_end = NULL;

  if (argc != 6) {
    print_help ();
    goto Exit;
  }

  var_name_len = AsciiStrSize (argv[3]);
  // The length returned by AsciiStrSize should already includes the null character
  var_name = malloc (var_name_len * sizeof (CHAR16));
  if (var_name == NULL) {
    printf ("Not able to allocate buffer for variable name.\n");
    goto Exit;
  }

  efi_st = AsciiStrToUnicodeStrS (argv[3], var_name, var_name_len * sizeof (CHAR16));
  if (EFI_ERROR (efi_st)) {
    printf ("Converting variable name to UNICODE string failed.\n");
    goto Exit;
  }

  efi_st = AsciiStrToGuid (argv[4], &var_guid);
  if (EFI_ERROR (efi_st)) {
    printf ("Parsing variable guid failed.\n");
    goto Exit;
  }

  if ((AsciiStrLen (argv[5]) >= 3) && (CompareMem (argv[5], "0x", 2) == 0)) {
    efi_st = AsciiStrHexToUint64S (argv[5], &var_attr_end, &var_attr64);
  } else {
    efi_st = AsciiStrDecimalToUint64S (argv[5], &var_attr_end, &var_attr64);
  }

  if (EFI_ERROR (efi_st) || var_attr_end == argv[5]) {
    printf ("Parsing variable attribute failed.\n");
    goto Exit;
  }

  return_val = work (argv[1], argv[2], var_name, &var_guid, (UINT32)var_attr64);

Exit:
  if (var_name != NULL) {
    free (var_name);
  }

  return return_val;
}

int
work (
  CHAR8     *db_filename,
  CHAR8     *key_filename,
  CHAR16    *variable_name,
  EFI_GUID  *var_guid,
  UINT32    var_attr
  )
{
  errno_t                        err               = 0;
  UINT8                          *db_buf           = NULL;
  UINTN                          db_size           = 0;
  EFI_VARIABLE_AUTHENTICATION_2  *var_auth         = NULL;
  UINTN                          db_cert_data_size = 0;
  UINT8                          *db_cert_data     = NULL;
  UINT8                          *trusted_cert     = NULL;
  UINTN                          trusted_cert_size = 0;
  UINT8                          *kek_buf          = NULL;
  UINTN                          kek_size          = 0;
  EFI_SIGNATURE_LIST             *cert_list        = NULL;
  EFI_SIGNATURE_DATA             *cert             = NULL;
  UINTN                          idx               = 0;
  UINTN                          cert_count        = 0;
  UINT8                          *hashed_data      = NULL;
  UINT8                          *data_pointer     = NULL;
  UINTN                          hashed_data_size  = 0;
  UINTN                          copy_length       = 0;
  UINT8                          *payload          = NULL;
  UINTN                          payload_size      = 0;
  BOOLEAN                        verify_result     = FALSE;

  err = read_file_to_buf (db_filename, &db_buf, &db_size);
  if (err != 0) {
    goto Exit;
  }

  var_auth = (EFI_VARIABLE_AUTHENTICATION_2 *)db_buf;
  // If the authentication header does not includes a pkcs7 signed data, or
  // doesn't exist. Abort the process.
  if ((db_size < sizeof (EFI_VARIABLE_AUTHENTICATION_2)) || !CompareGuid ((void *)&gEfiCertPkcs7Guid, (void *)&(var_auth->AuthInfo.CertType))) {
    printf ("The db file does not have a pkcs7 authentication header\n");
    err = 1;
    goto Exit;
  }

  db_cert_data_size = (UINTN)var_auth->AuthInfo.Hdr.dwLength - OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData);
  db_cert_data      = (UINT8 *)(&var_auth->AuthInfo.CertData[0]);

  payload      = db_cert_data + db_cert_data_size;
  payload_size = db_size - ((OFFSET_OF (EFI_VARIABLE_AUTHENTICATION_2, AuthInfo)) + (OFFSET_OF (WIN_CERTIFICATE_UEFI_GUID, CertData))) - (UINTN)db_cert_data_size;

  // Prepare data blob to be hashed
  hashed_data_size = payload_size + sizeof (EFI_TIME) + sizeof (UINT32) +
                     sizeof (EFI_GUID) + StrSize (variable_name) - sizeof (CHAR16);
  hashed_data = malloc (hashed_data_size);
  if (hashed_data == NULL) {
    err = 1;
    printf ("Unable to allocate buffer for hash data.\n");
    goto Exit;
  }

  data_pointer = hashed_data;
  copy_length  = StrLen (variable_name) * sizeof (CHAR16);
  CopyMem (data_pointer, variable_name, copy_length);
  data_pointer += copy_length;

  copy_length = sizeof (EFI_GUID);
  CopyMem (data_pointer, var_guid, copy_length);
  data_pointer += copy_length;

  copy_length = sizeof (UINT32);
  CopyMem (data_pointer, &var_attr, copy_length);
  data_pointer += copy_length;

  copy_length = sizeof (EFI_TIME);
  CopyMem (data_pointer, &var_auth->TimeStamp, copy_length);
  data_pointer += copy_length;

  CopyMem (data_pointer, payload, payload_size);

  // Read PK / KEK file that contains trusted certificates.
  err = read_file_to_buf (key_filename, &kek_buf, &kek_size);
  if (err != 0) {
    goto Exit;
  }

  var_auth = (EFI_VARIABLE_AUTHENTICATION_2 *)kek_buf;
  if ((kek_size < sizeof (EFI_VARIABLE_AUTHENTICATION_2)) || CompareGuid ((void *)&gEfiCertPkcs7Guid, (void *)&(var_auth->AuthInfo.CertType))) {
    // kek has a auth header, skip it since we don't care the integrity of the key itself.
    cert_list = (EFI_SIGNATURE_LIST *)(kek_buf + sizeof (EFI_TIME) + var_auth->AuthInfo.Hdr.dwLength);
  } else {
    // kek doesn't has a auth header.
    cert_list = (EFI_SIGNATURE_LIST *)kek_buf;
  }

  while ((UINTN)cert_list - (UINTN)kek_buf < kek_size) {
    // Only X509 certificate type can be used to validate the signature.
    if (CompareGuid (&cert_list->SignatureType, &gEfiCertX509Guid)) {
      cert       = (EFI_SIGNATURE_DATA *)((UINT8 *)cert_list + sizeof (EFI_SIGNATURE_LIST) + cert_list->SignatureHeaderSize);
      cert_count = (cert_list->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - cert_list->SignatureHeaderSize) / cert_list->SignatureSize;
      for (idx = 0; idx < cert_count; idx++) {
        trusted_cert      = cert->SignatureData;
        trusted_cert_size = cert_list->SignatureSize - (sizeof (EFI_SIGNATURE_DATA) - 1);
        verify_result     = Pkcs7Verify (
                                         db_cert_data,
                                         db_cert_data_size,
                                         trusted_cert,
                                         trusted_cert_size,
                                         hashed_data,
                                         hashed_data_size
                                         );
        if (verify_result) {
          err = 0;
          printf ("Verify passed with certificate: ");
          print_x509_info (trusted_cert, trusted_cert_size);
          goto Exit;
        }

        cert = (EFI_SIGNATURE_DATA *)((UINT8 *)cert + cert_list->SignatureSize);
      }
    }

    cert_list = (EFI_SIGNATURE_LIST *)((UINT8 *)cert_list + cert_list->SignatureListSize);
  }

  err = 2;
  printf ("Not able to find a matching cert\n");

Exit:
  if (db_buf != NULL) {
    free (db_buf);
  }

  if (kek_buf != NULL) {
    free (kek_buf);
  }

  if (hashed_data != NULL) {
    free (hashed_data);
  }

  return err;
}

errno_t
read_file_to_buf (
  char     *filename,
  uint8_t  **buf,
  size_t   *filesize
  )
{
  FILE     *stream = NULL;
  long     filesize_loc;
  size_t   read_size;
  void     *file_buf = NULL;
  errno_t  err       = 0;

  err = fopen_s (&stream, filename, "rb");
  if (err != 0) {
    printf ("Open file %s failed\n", filename);
    goto Exit;
  }

  fseek (stream, 0L, SEEK_END);
  filesize_loc = ftell (stream);
  file_buf     = malloc ((size_t)filesize_loc);
  if (file_buf == 0) {
    printf ("Allocate buffer to read %s failed\n", filename);
    err = 1;
    goto Exit;
  }

  fseek (stream, 0L, SEEK_SET);
  read_size = fread_s ((void *)file_buf, filesize_loc, 1, filesize_loc, stream);
  if (read_size != filesize_loc) {
    printf ("Not able to read the entire file. err = %d\n", ferror (stream));
    err = 1;
    goto Exit;
  }

  *buf      = file_buf;
  *filesize = (size_t)filesize_loc;
  fclose (stream);
  return 0;

Exit:
  if (stream != NULL) {
    fclose (stream);
  }

  if (file_buf != NULL) {
    free (file_buf);
  }

  return err;
}

#define COMMON_NAME_SIZE  250
void
print_x509_info (
  UINT8  *cert,
  UINTN  cert_size
  )
{
  CHAR8       common_name[COMMON_NAME_SIZE];
  UINTN       common_name_size = COMMON_NAME_SIZE;
  EFI_STATUS  success;

  common_name_size = COMMON_NAME_SIZE;
  success          = X509GetCommonName (cert, cert_size, common_name, &common_name_size);
  if (EFI_ERROR (success)) {
    printf ("Not able to get subject name\n");
    return;
  } else {
    printf ("%s\n", common_name);
    {
      errno_t  err;
      FILE     *stream = NULL;
      err = fopen_s (&stream, common_name, "wb");
      if (err) {
        printf ("Not able to write %s\n", common_name);
      } else {
        fwrite (cert, cert_size, 1, stream);
      }

      if (stream != NULL) {
        fclose (stream);
        stream = NULL;
      }
    }
  }
}
