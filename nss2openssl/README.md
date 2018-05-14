# Replacing NSS by OpenSLL

## Contents

1. [Introduction](#introduction)
1. [`libvolume_key` Binds to NSS Stack/GPGME/Itself](#)

## Introduction

Notes about attempt to replace NSS stack by OpenSLL in `volume_key`.

## `libvolume_key` Binds to NSS Stack/GPGME/Itself

Summary of what calls what in `volume_key`. Following per-each-c-or-h-file maps mets the format:
```
<defined function or macro name> ":" (
    <volume_key function>
|   <volume_key macro>
|   <NSS stack function>
|   <GPGME function>
)*
```

The line numbers refer to upstream changeset [`ecef526a51c5a276681472fd6df239570c9ce518`](https://pagure.io/volume_key/c/ecef526a51c5a276681472fd6df239570c9ce518?branch=master).

### `crypto.h` and `crypto.c`

`crypto.h` contains declarations.

`crypto.c` uses these NSS/GPGME/libvolume_key functions:
```
error_from_pr:                                      [line 45]
    libvk_nss_error_text__
    PR_GetError
    PR_ErrorToString
    PR_GetErrorTextLength
    PR_GetErrorText

encrypt_asymmetric:                                 [line 79]
    NSS_CMSMessage_Create
    error_from_pr
    NSS_CMSEnvelopedData_Create
    NSS_CMSMessage_GetContentInfo
    NSS_CMSContentInfo_SetContent_EnvelopedData
    NSS_CMSEnvelopedData_Destroy
    NSS_CMSRecipientInfo_Create
    NSS_CMSEnvelopedData_AddRecipient
    NSS_CMSRecipientInfo_Destroy
    NSS_CMSEnvelopedData_GetContentInfo
    NSS_CMSContentInfo_SetContent_Data
    PORT_NewArena
    NSS_CMSEncoder_Start
    NSS_CMSEncoder_Update
    NSS_CMSEncoder_Finish
    PORT_FreeArena
    NSS_CMSMessage_Destroy

decrypt_asymmetric:                                 [line 210]
    SECITEM_AllocItem
    error_from_pr
    NSS_CMSMessage_CreateFromDER
    NSS_CMSMessage_GetContent
    NSS_CMSMessage_Destroy
    SECITEM_FreeItem

wrap_asymmetric:                                    [line 261]
    PK11_GetBestSlot
    error_from_pr
    PK11_ImportSymKey
    PK11_FreeSlot
    PORT_NewArena
    CERT_GetCertIssuerAndSN
    CERT_ExtractPublicKey
    SECKEY_PublicKeyStrength
    SECITEM_AllocItem
    PK11_PubWrapSymKey
    SECKEY_DestroyPublicKey
    PK11_FreeSymKey
    SECITEM_FreeItem
    PORT_FreeArena

unwrap_asymmetric:                                  [line 372]
    CERT_FindCertByIssuerAndSN
    CERT_GetDefaultCertDB
    PK11_GetInternalKeySlot
    error_from_pr
    CERT_DestroyCertificate
    PK11_FindPrivateKeyFromCert
    PK11_FreeSlot
    PK11_PubUnwrapSymKey
    SECKEY_DestroyPrivateKey
    PK11_ExtractKeyValue
    PK11_GetKeyData
    PK11_FreeSymKey

wrap_symmetric:                                     [line 451]
    PK11_GetBestSlot
    error_from_pr
    PK11_ImportSymKey
    PK11_FreeSlot
    PK11_GenerateNewParam
    SECITEM_AllocItem
    PK11_WrapSymKey
    PK11_FreeSymKey
    PK11_IVFromParam
    SECITEM_FreeItem

unwrap_symmetric:                                   [line 529]
    PK11_ParamFromIV
    error_from_pr
    PK11_UnwrapSymKey
    SECITEM_FreeItem
    PK11_ExtractKeyValue
    PK11_GetKeyData
    PK11_FreeSymKey

error_from_gpgme:                                   [line 580]
    gpgme_strerror_r
    gpgme_strsource

gpgme_passphrase_cb:                                [line 600]
    gpgme_error_from_errno

init_gpgme:                                         [line 631]
    gpgme_check_version
    gpgme_new
    error_from_gpgme
    gpgme_set_locale
    gpgme_set_protocol
    gpgme_ctx_set_engine_info
    gpgme_set_passphrase_cb
    gpgme_passphrase_cb
    gpgme_release

encrypt_with_passphrase:                            [line 683]
    init_gpgme
    gpgme_data_new_from_mem
    error_from_gpgme
    gpgme_data_new
    gpgme_op_encrypt
    gpgme_data_release
    gpgme_data_release_and_get_mem
    gpgme_free
    gpgme_release

decrypt_with_passphrase:                            [line 740]
    init_gpgme
    gpgme_data_new_from_mem
    error_from_gpgme
    gpgme_data_new
    gpgme_op_decrypt
    gpgme_data_release
    gpgme_data_release_and_get_mem
    gpgme_free
    gpgme_release
```

### `kmip.h` and `kmip.c`

`kmip.h` contains declarations.

`kmip.c` uses these NSS/GPGME/libvolume_key functions:
```
kmip_crypto_params_free:                            [line 38]

kmip_attribute_free:                                [line 45]
    kmip_crypto_params_free

kmip_symmetric_key_free:                            [line 64]

kmip_key_value_free_v:                              [line 76]
    kmip_symmetric_key_free

kmip_key_value_set_bytes:                           [line 96]
    kmip_key_value_free_v

kmip_key_value_set_symmetric_key:                   [line 107]
    kmip_key_value_free_v

kmip_key_value_free:                                [line 119]
    kmip_key_value_free_v
    kmip_attribute_free

kmip_encryption_key_info_free:                      [line 135]
    kmip_crypto_params_free

kmip_key_wrapping_data_free:                        [line 145]
    kmip_encryption_key_info_free

kmip_key_block_set_clear_secret:                    [line 156]
    kmip_key_value_set_symmetric_key
    kmip_key_value_set_bytes
    kmip_key_wrapping_data_free

kmip_key_block_free:                                [line 186]
    kmip_key_value_free
    kmip_key_wrapping_data_free

kmip_object_symmetric_key_free:                     [line 197]
    kmip_key_block_free

kmip_object_secret_data_free:                       [line 206]
    kmip_key_block_free

kmip_protocol_version_free:                         [line 215]

kmip_libvk_packet_free:                             [line 222]
    kmip_protocol_version_free
    kmip_object_symmetric_key_free
    kmip_object_secret_data_free

add_data:                                           [line 249]

add_ttlv:                                           [line 268]
    add_data

add_int32:                                          [line 286]
    add_ttlv

add_enum:                                           [line 298]
    add_ttlv

add_string:                                         [line 310]
    add_ttlv

add_bytes:                                          [line 335]
    add_ttlv

se_start:                                           [line 357]
    add_data

se_end:                                             [line 383]

kmip_encode_crypto_params:                          [line 408]
    se_start
    add_enum
    se_end

kmip_encode_attribute:                              [line 436]
    se_start
    add_string
    add_enum
    add_int32
    kmip_encode_crypto_params
    se_end

kmip_encode_symmetric_key:                          [line 488]
    se_start
    add_bytes
    se_end

kmip_encode_key_value:                              [line 504]
    se_start
    add_bytes
    kmip_encode_symmetric_key
    kmip_encode_attribute
    se_end

kmip_encode_encryption_key_info:                    [line 544]
    se_start
    add_string
    kmip_encode_crypto_params
    se_end

kmip_encode_key_wrapping_data:                      [line 566]
    se_start
    add_enum
    kmip_encode_encryption_key_info
    add_bytes
    se_end

kmip_encode_key_block:                              [line 592]
    se_start
    add_enum
    kmip_encode_key_value
    add_int32
    kmip_encode_key_wrapping_data
    se_end

kmip_encode_object_symmetric_key:                   [line 629]
    se_start
    kmip_encode_key_block
    se_end

kmip_encode_object_secret_data:                     [line 646]
    se_start
    add_enum
    kmip_encode_key_block
    se_end

kmip_encode_protocol_version:                       [line 664]
    se_start
    add_int32
    se_end

kmip_encode_libvk_packet:                           [line 683]
    se_start
    kmip_encode_protocol_version
    add_enum
    kmip_encode_object_symmetric_key
    kmip_encode_object_secret_data
    se_end

kmip_next_tag_is:                                   [line 720]

get_data:                                           [line 733]

get_ttlv:                                           [line 751]
    get_data

get_int32:                                          [line 788]
    get_ttlv

get_enum:                                           [line 803]
    get_ttlv

get_string:                                         [line 828]
    get_data

get_bytes:                                          [line 886]
    get_data

sd_start:                                           [line 934]
    get_data

sd_end:                                             [line 973]

kmip_decode_crypto_params:                          [line 987]
    sd_start
    kmip_next_tag_is
    get_enum
    sd_end
    kmip_crypto_params_free

kmip_decode_attribute:                              [line 1034]
    sd_start
    get_string
    get_enum
    get_int32
    kmip_decode_crypto_params
    sd_end
    kmip_attribute_free

kmip_decode_symmetric_key:                          [line 1103]
    sd_start
    get_bytes
    sd_end
    kmip_symmetric_key_free

kmip_decode_key_value:                              [line 1127]
    sd_start
    get_bytes
    kmip_decode_symmetric_key
    kmip_decode_attribute
    sd_end
    kmip_key_value_free

kmip_decode_encryption_key_info:                    [line 1179]
    sd_start
    get_string
    kmip_next_tag_is
    kmip_decode_crypto_params
    sd_end
    kmip_encryption_key_info_free

kmip_decode_key_wrapping_data:                      [line 1212]
    sd_start
    get_enum
    kmip_next_tag_is
    kmip_decode_encryption_key_info
    get_bytes
    sd_end
    kmip_key_wrapping_data_free

kmip_decode_key_block:                              [line 1256]
    sd_start
    get_enum
    kmip_decode_key_value
    kmip_next_tag_is
    get_int32
    kmip_decode_key_wrapping_data
    sd_end
    kmip_key_block_free

kmip_decode_object_symmetric_key:                   [line 1331]
    sd_start
    kmip_decode_key_block
    sd_end
    kmip_object_symmetric_key_free

kmip_decode_object_secret_data:                     [line 1364]
    sd_start
    get_enum
    kmip_decode_key_block
    sd_end
    kmip_object_secret_data_free

kmip_decode_protocol_version:                       [line 1400]
    sd_start
    get_int32
    sd_end
    kmip_protocol_version_free

kmip_decode_libvk_packet:                           [line 1437]
    sd_start
    kmip_decode_protocol_version
    get_enum
    kmip_decode_object_symmetric_key
    kmip_decode_object_secret_data
    sd_end
    kmip_libvk_packet_free

kmip_libvk_packet_decode:                           [line 1523]
    kmip_decode_libvk_packet
    kmip_libvk_packet_free

kmip_libvk_packet_drop_secret:                      [line 1549]
    kmip_key_value_free_v
    kmip_key_wrapping_data_free

kmip_libvk_packet_encode:                           [line 1588]
    kmip_encode_libvk_packet

kmip_libvk_packet_wrap_secret_asymmetric:           [line 1613]
    wrap_asymmetric
    kmip_key_value_set_bytes

kmip_libvk_packet_unwrap_secret_asymmetric:         [line 1709]
    unwrap_asymmetric
    kmip_key_block_set_clear_secret

kmip_libvk_packet_wrap_secret_symmetric:            [line 1811]
    PK11_GetMechanism
    wrap_symmetric
    kmip_key_value_set_bytes
    PK11_GetKeyLength

kmip_libvk_packet_unwrap_secret_symmetric:          [line 1901]
    unwrap_symmetric
    kmip_key_block_set_clear_secret

kmip_dump_sub:                                      [line 1982]
    kmip_dump_sub

kmip_dump:                                          [line 2195]
    kmip_dump_sub
```

### `libvolume_key.h` and `libvolume_key.c`

`libvolume_key.h` contains declarations.

`libvolume_key.c` uses these NSS/GPGME/libvolume_key functions:
```
libvk_init:                                         [line 30]

libvk_error_quark:                                  [line 36]

packet_prepend_header:                              [line 54]

libvk_volume_create_packet_cleartext:               [line 77]
    volume_create_escrow_packet
    kmip_libvk_packet_encode
    kmip_libvk_packet_free
    packet_prepend_header

libvk_volume_create_packet_asymmetric:              [line 114]
    libvk_volume_create_packet_asymmetric_with_format

libvk_volume_create_packet_assymetric:              [line 134]
    libvk_volume_create_packet_asymmetric

libvk_volume_create_packet_asymmetric_with_format:  [line 151]
    volume_create_escrow_packet
    kmip_libvk_packet_encode
    encrypt_asymmetric
    kmip_libvk_packet_wrap_secret_asymmetric
    kmip_libvk_packet_free
    packet_prepend_header

libvk_volume_create_packet_with_passphrase:         [line 226]
    volume_create_escrow_packet
    kmip_libvk_packet_encode
    kmip_libvk_packet_free
    encrypt_with_passphrase
    packet_prepend_header

libvk_volume_create_packet_wrap_secret_symmetric:   [line 270]
    volume_create_escrow_packet
    kmip_libvk_packet_wrap_secret_symmetric
    kmip_libvk_packet_encode
    kmip_libvk_packet_free
    packet_prepend_header

libvk_packet_get_format:                            [line 312]

libvk_packet_open:                                  [line 348]
    libvk_packet_get_format
    kmip_libvk_packet_decode
    decrypt_asymmetric
    ui_get_passphrase
    decrypt_with_passphrase
    kmip_libvk_packet_unwrap_secret_asymmetric
    ui_get_sym_key
    kmip_libvk_packet_unwrap_secret_symmetric
    volume_load_escrow_packet
    kmip_libvk_packet_free

libvk_packet_open_unencrypted:                      [line 487]
    libvk_packet_get_format
    kmip_libvk_packet_decode
    kmip_libvk_packet_drop_secret
    volume_load_escrow_packet
    kmip_libvk_packet_free
```

### `nss_error.h`, `SECerrs.h`, `SSLerrs.h`, and `nss_error.c`

`nss_error.h` contains declarations.

`SECerrs.h` and `SSLerrs.h` contain error codes.

`nss_error.c` uses these NSS/GPGME/libvolume_key functions:
```
libvk_nss_error_text__:                             [line 43]
```

### `ui.h` and `ui.c`

`ui.h` contains declarations.

`ui.c` uses these NSS/GPGME/libvolume_key functions:
```
libvk_ui_new:                                       [line 27]

libvk_ui_free:                                      [line 34]

libvk_ui_set_generic_cb:                            [line 58]

libvk_ui_set_passphrase_cb:                         [line 81]

libvk_ui_set_nss_pwfn_arg:                          [line 99]

libvk_ui_set_sym_key_cb:                            [line 119]

ui_get_passphrase:                                  [line 136]

ui_get_sym_key:                                     [line 161]
```

### `volume.h` and `volume.c`

`volume.h` contains declarations.

`volume.c` uses these NSS/GPGME/libvolume_key functions:
```
add_attribute_strings:                              [line 37]

add_common_volume_attributes:                       [line 52]
    add_attribute_strings

volume_create_data_encryption_key_packet:           [line 74]
    add_common_volume_attributes
    kmip_key_value_free

volume_create_passphrase_packet:                    [line 123]
    add_common_volume_attributes

get_attribute_strings:                              [line 157]

get_attribute:                                      [line 179]

libvk_vp_free:                                      [line 208]

libvk_vp_get_label:                                 [line 221]

libvk_vp_get_name:                                  [line 231]

libvk_vp_get_type:                                  [line 241]

libvk_vp_get_value:                                 [line 253]

add_vp:                                             [line 263]

libvk_volume_free:                                  [line 280]
    luks_volume_free

libvk_volume_open:                                  [line 300]
    luks_volume_open
    libvk_volume_free

libvk_volume_get_hostname:                          [line 357]

libvk_volume_get_uuid:                              [line 367]

libvk_volume_get_label:                             [line 377]

libvk_volume_get_path:                              [line 389]

libvk_volume_get_format:                            [line 402]

libvk_volume_dump_properties:                       [line 415]
    add_vp
    luks_volume_dump_properties

libvk_volume_get_secret:                            [line 443]
    luks_get_secret

libvk_packet_match_volume:                          [line 469]
    luks_packet_match_volume

libvk_volume_load_packet:                           [line 549]
    libvk_packet_match_volume
    luks_load_packet

libvk_volume_apply_packet:                          [line 580]
    libvk_packet_match_volume
    luks_apply_secret

libvk_volume_add_secret:                            [line 615]
    luks_add_secret

libvk_volume_open_with_packet:                      [line 643]
    libvk_packet_match_volume
    luks_open_with_packet

volume_load_escrow_packet:                          [line 674]
    get_attribute_strings
    luks_parse_escrow_packet
    libvk_volume_free

volume_create_escrow_packet:                        [line 761]
    luks_create_escrow_packet
```

### `volume_luks.h` and `volume_luks.c`

`volume_luks.h` contains declarations.

`volume_luks.c` uses these NSS/GPGME/libvolume_key functions:
```
my_strerror:                                        [line 37]

error_from_cryptsetup:                              [line 66]
    my_strerror

record_cryptsetup_log_entry:                        [line 82]

open_crypt_device:                                  [line 98]
    record_cryptsetup_log_entry
    error_from_cryptsetup

g_free_passphrase:                                  [line 127]

g_free_key:                                         [line 135]

luks_replace_key:                                   [line 143]

luks_replace_passphrase:                            [line 158]
    g_free_passphrase

luks_volume_free:                                   [line 170]
    g_free_passphrase

luks_volume_open:                                   [line 187]
    open_crypt_device

luks_volume_dump_properties:                        [line 226]
    add_vp

luks_get_secret:                                    [line 273]
    open_crypt_device
    ui_get_passphrase
    g_free_passphrase
    error_from_cryptsetup
    luks_replace_key
    g_free_key
    luks_replace_passphrase

luks_packet_match_volume:                           [line 361]

luks_load_packet:                                   [line 400]
    open_crypt_device
    error_from_cryptsetup
    luks_replace_key
    luks_replace_passphrase
    g_free_key

luks_apply_secret:                                  [line 472]
    ui_get_passphrase
    g_free_passphrase
    open_crypt_device
    error_from_cryptsetup
    luks_replace_key
    luks_replace_passphrase

luks_add_secret:                                    [line 571]
    open_crypt_device
    error_from_cryptsetup
    luks_replace_passphrase

add_attribute_luks_crypto_algorithm:                [line 618]

add_attribute_luks_crypto_params:                   [line 636]

luks_create_escrow_packet:                          [line 676]
    volume_create_data_encryption_key_packet
    add_attribute_strings
    add_attribute_luks_crypto_algorithm
    add_attribute_luks_crypto_params
    volume_create_passphrase_packet

luks_parse_escrow_packet:                           [line 740]
    get_attribute_strings
    get_attribute

luks_open_with_packet:                              [line 854]
    open_crypt_device
    error_from_cryptsetup
    g_free_key
```

## `volume_key` Utility

### `volume_key.c`

```
error_exit:                                         [line 49]

yes_or_no:                                          [line 64]

error_from_pr:                                      [line 109]
    libvk_nss_error_text__
    PR_GetError
    PR_ErrorToString
    PR_GetErrorTextLength
    PR_GetErrorText

parse_options:                                      [line 261]
    error_exit

read_batch_string:                                  [line 376]

get_password:                                       [line 400]

nss_password_fn:                                    [line 459]
    PK11_GetTokenName
    get_password
    read_batch_string
    PL_strdup

generic_ui_cb:                                      [line 486]
    read_batch_string
    get_password

passphrase_ui_cb:                                   [line 537]
    read_batch_string
    get_password

create_ui:                                          [line 561]
    libvk_ui_new
    libvk_ui_set_generic_cb
    generic_ui_cb
    libvk_ui_set_passphrase_cb
    passphrase_ui_cb

open_packet_file:                                   [line 576]
    libvk_packet_open

pos_init:                                           [line 607]
    CERT_DecodeCertFromPackage
    error_from_pr

pos_interact:                                       [line 646]
    passphrase_ui_cb

pos_free:                                           [line 706]
    CERT_DestroyCertificate

write_packet:                                       [line 716]
    libvk_volume_create_packet_cleartext
    libvk_volume_create_packet_asymmetric_with_format
    libvk_volume_create_packet_with_passphrase

output_packet:                                      [line 749]
    write_packet

generate_random_passphrase:                         [line 769]
    PK11_GenerateRandom
    error_from_pr
    error_exit

do_save:                                            [line 813]
    error_exit
    pos_init
    libvk_volume_open
    create_ui
    open_packet_file
    libvk_volume_load_packet
    libvk_volume_free
    libvk_volume_get_secret
    pos_interact
    output_packet
    generate_random_passphrase
    libvk_volume_add_secret
    write_packet
    pos_free
    libvk_ui_free

packet_matches_volume:                              [line 874]
    libvk_packet_match_volume
    yes_or_no

do_restore:                                         [line 945]
    error_exit
    libvk_volume_open
    create_ui
    open_packet_file
    packet_matches_volume
    libvk_volume_apply_packet
    libvk_volume_free
    libvk_ui_free

do_setup_volume:                                    [line 982]
    error_exit
    libvk_volume_open
    create_ui
    open_packet_file
    libvk_ui_free
    packet_matches_volume
    libvk_volume_open_with_packet
    libvk_volume_free

do_reencrypt:                                       [line 1018]
    error_exit
    pos_init
    create_ui
    open_packet_file
    pos_interact
    output_packet
    pos_free
    libvk_volume_free
    libvk_ui_free

do_dump:                                            [line 1047]
    error_exit
    libvk_packet_get_format
    libvk_packet_open_unencrypted
    create_ui
    libvk_packet_open
    libvk_ui_free
    libvk_volume_dump_properties
    libvk_vp_get_type
    libvk_vp_get_label
    libvk_vp_get_value
    libvk_vp_free
    libvk_volume_free

main:                                               [line 1139]
    parse_options
    PR_Init
    PK11_SetPasswordFunc
    nss_password_fn
    NSS_Init
    NSS_NoDB_Init
    error_from_pr
    error_exit
    libvk_init
    do_save
    do_restore
    do_setup_volume
    do_reencrypt
    do_dump
    NSS_Shutdown
```
