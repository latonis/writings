# 100 Days of Yara in 2024: Day 18
Today is the first day we don't have a finished piece of work ready for the daily blog post. Instead, I have an update on the work that is going well: code signing data for Mach-O binaries. 

If you're unfamiliar with how the code signing data is stored, there's a big blob pointed to by a `LC_CODE_SIGNATURE` load command. This load command then has a `data_offset` field and a `data_size` field, which allow us to know where the big signature blob is at in the binary as well as how big it is.

I naively assumed that this would be fairly straight forward, all we need to do is look for the magic header for the certificate blob and then parse it out into memory and notate the things we need to. Wrong! I had to dive into encoding formats, and wow did I learn a lot!

I started off here: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1. This allowed to have a working knowledge of what we should be expecting when parsing the blob.

Later I discovered that Apple uses Cryptographic Message Syntax (CMS / [RFC 5652](https://datatracker.ietf.org/doc/html/rfc5652)) for storing our particular blobs of certificate data.

The super blob is structured as so:

```c
typedef struct __SC_SuperBlob {
    uint32_t magic;                         /* magic number */
    uint32_t length;                        /* total length of SuperBlob */
    uint32_t count;                         /* number of index entries following */
    CS_BlobIndex index[];                   /* (count) entries */
    /* followed by Blobs in no particular order as indicated by offsets in index */
} CS_SuperBlob
```
Once the super blob is parsed, we can iterate through the blob index structures:

```c
typedef struct __BlobIndex {
	uint32_t type;					/* type of entry */
	uint32_t offset;				/* offset of entry */
} CS_BlobIndex;
```

Then, we can parse the blobs pointed to by the blob indexes:
```c
struct CS_Blob {
    uint32_t magic;                 // magic number
    uint32_t length;                // total length of blob
};
```

The particular magic bytes we're looking for: `CSMAGIC_BLOBWRAPPER = 0xfade0b01`. Once we find this, we know we have a CMS blob in BER (maybe DER too?) format.

I'll dive into the parsing more once I have a finished PR, however we are well on our way to parsing all of the certificates for the signer, up to the root certificate.

## BER and DER
A lot of this work went into understanding how Apple stores their code signature data in the binary. In theory, it sounds as simple as just parsing the certificate that is embedded in the Mach-O. 

It didn't turn out to be quite that simple. Almost every cryptography library for CMS or X.509 certificates expected the certificate to be in DER format, which to my understanding is a encoding format for ASN.1 which has a definite length defined for the encoding, where as BER does not. All of the libraries I looked into for parsing these certificates were failing as they expected a definite length (DER) format certificate, and Apple appears (I think) to use BER format for the certificate. This means I was always erroring out when attempting to parse the certificates. I need to explore this more, as I am not sure if Apple only uses BER or if it can also be DER (time to hunt down more test samples!). Maybe we will need to convert BER format to DER? who knows!

[Reference here for BER and DER](https://www.itu.int/rec/T-REC-X.690-202102-I/en)

## More References:
I scoured a lot of information looking for examples, context, and more on how to parse these certs. I found a lot of parsers for Mach-O (almost all?) didn't choose to or didn't know how to parse these. I will write a more in-depth parsing description later with the PR to YARA-X.

- https://opensource.apple.com/source/dyld/dyld-433.5/interlinked-dylibs/CodeSigningTypes.h.auto.html
- https://opensource.apple.com/source/Security/Security-55471/sec/Security/Tool/codesign.c.auto.html
- https://github.com/qyang-nj/llios/blob/main/macho_parser/docs/LC_CODE_SIGNATURE.md
- https://gregoryszorc.com/docs/apple-codesign/0.17.0/apple_codesign_concepts.html
  
## Finished Work

I don't have a PR to end this blog with unfortunately, as it is still a WIP, but I can provide a screenshot here to show I've finally got the certificates being parsed.

![parsed certificate for Mach-O binary](/static/images/100-days-of-yara-2024-day-18/image.png)

The entries are as follows once parsed out and converted to strings:
- $Developer ID Certification Authority
- Apple Certification Authority
- Apple Inc.
- US
