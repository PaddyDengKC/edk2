## @file
# UnitTestFrameworkPkg
#
# Copyright (c) 2019 - 2021, Intel Corporation. All rights reserved.<BR>
# Copyright (c) 2020, Hewlett Packard Enterprise Development LP. All rights reserved.<BR>
# Copyright (c) 2022, Loongson Technology Corporation Limited. All rights reserved.<BR>
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

[Defines]
  PLATFORM_NAME           = ChechDb
  PLATFORM_GUID           = c8265fcc-7cdf-4944-8a56-ef2481436cf1
  PLATFORM_VERSION        = 1.00
  DSC_SPECIFICATION       = 0x00010005
  OUTPUT_DIRECTORY        = Build/UnitTestFrameworkPkg/Host
  SUPPORTED_ARCHITECTURES = IA32|X64
  BUILD_TARGETS           = NOOPT|RELEASE
  SKUID_IDENTIFIER        = DEFAULT

!include UnitTestFrameworkPkg/UnitTestFrameworkPkgHost.dsc.inc

[LibraryClasses.common.HOST_APPLICATION]
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/UnitTestHostBaseCryptLib.inf
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLibFull.inf
  RngLib|MdePkg/Library/BaseRngLib/BaseRngLib.inf

[Components]
  UnitTestFrameworkPkg/CheckDb/CheckDb.inf

# [BuildOptions.common.EDKII.HOST_APPLICATION]
#   MSFT:*_*_IA32_DLINK_FLAGS = /MACHINE:I386
#   MSFT:*_*_X64_DLINK_FLAGS = /MACHINE:AMD64
