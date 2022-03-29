#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <cmath>

using namespace std;

#define FOREGROUND_WHITE FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN

void setColour(int colour) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), colour);
}


#pragma pack(push,1)
struct VolumeHeader {
    uint8_t     jump[3]; 
    char        VolumeSystemSignature[8];
    uint16_t    bytesPerSector;
    uint8_t     sectorsPerCluster;
    uint16_t    reservedSectors;
    uint8_t     ignore0[3];
    uint16_t    ignore1;
    uint8_t     media;
    uint16_t    ignore2;
    uint16_t    sectorsPerTrack;
    uint16_t    headsPerCylinder;
    uint32_t    hiddenSectors;
    uint32_t    ignore3;
    uint32_t    ignore4;
    uint64_t    totalSectors;
    uint64_t    mftClusterBlockNumber;
    uint64_t    mftMirrorClusterBlockNumber;
    uint32_t    mftSize;
    uint32_t    clustersPerIndexBlock;
    uint64_t    serialNumber;
    uint32_t    checksum;
    uint8_t     bootloader[426];
    uint16_t    bootSignature;
};
static_assert(sizeof(VolumeHeader) == 512 );



//enum for entry flags
enum MFTEntryFlags {
    FILE_RECORD_SEGMENT_IN_USE = 0x0001,
    MFT_RECORD_IN_USE = 0x0001,
    FILE_NAME_INDEX_PRESENT = 0x0002,
    MFT_RECORD_IS_DIRECTORY = 0x0002,
    MFT_RECORD_IN_EXTEND = 0x0004,
    MFT_RECORD_IS_VIEW_INDEX = 0x0008
};

//MFT Attribute Data Flags
enum MFTAttributeFlags {
    ATTRIBUTE_IS_COMPRESSED = 0x0001,
    ATTRIBUTE_FLAG_COMPRESSION_MASK = 0x00ff,
    ATTRIBUTE_FLAG_ENCRYPTED = 0x4000,
    ATTRIBUTE_FLAG_SPARSE = 0x8000
};



inline MFTEntryFlags operator|(MFTEntryFlags a, MFTEntryFlags b)
{
    return static_cast<MFTEntryFlags>(static_cast<int>(a) | static_cast<int>(b));
}


struct MFTAttributeHeader {
    uint32_t attributeType;
    uint32_t size; //or record length
    uint8_t nonResidentFlag; //if this is 0, then the whole file is stored in the record. if it is 1, then the file data is stored elsewhere
    uint8_t nameLength;
    uint16_t nameOffset;
    uint16_t attributeDataFlags;
    uint16_t attributeIdentifier;
};

struct ResidentAttributeHeader : MFTAttributeHeader {
    uint32_t    attributeLength;
    uint16_t    attributeOffset;
    uint8_t     indexedFlag;
    uint8_t     ignore;
};



struct NonResidentAttributeHeader : MFTAttributeHeader {
    uint64_t    firstCluster;
    uint64_t    lastCluster; //if data size is 0 this can be -1
    uint16_t    dataRunsOffset;         // The offset in bytes from the start of attribute header to the description of where the attribute's contents can be found.
    uint16_t    compressionUnitSize;
    uint32_t    ignore;
    uint64_t    attributeAllocatedDataSize; //number of bytes allocated for the data
    uint64_t    attributeDataSize; //actual size in bytes
    uint64_t    streamDataSize;
};



struct MFTFileReference {
    uint8_t MFTEntryIndex[6]; //supossedly the index value is only 32 bit in size, will verify this in hxd
    uint16_t sequenceNumber;
};



struct MFTEntry {
    char signature[4];
    uint16_t fixupValuesOffset;
    uint16_t numberOfFixupValues;
    uint64_t metadataTransactionSequenceNumber;
    uint16_t sequenceNumber; //sequence number
    uint16_t linkCount;
    uint16_t attributesOffset; //Number of bytes between the start of the header and the first attribute header.
    uint16_t entryFlags; //is in use, is directory
    uint32_t usedEntrySize;
    uint32_t totalEntrySize;
    MFTFileReference baseRecordFileReference;
    uint16_t nextAttributeID;
    uint8_t ignore[2];
    uint32_t recordNumber; //index
};
static_assert(sizeof(MFTEntry) == 48 );

struct RunHeader
{
    uint8_t offset : 4;
    uint8_t length : 4;
};


#pragma pack(pop)


BOOL ReadToBuffer(HANDLE drive, void *buffer, uint64_t starting_point, uint64_t count) {
    DWORD bytesAccessed;
    LONG high = starting_point >> 32;
    SetFilePointer(drive, starting_point & 0xFFFFFFFF, &high, 0); //set file pointer to beginning of target

    return ReadFile(drive, buffer, count, &bytesAccessed, NULL); //read data of size: count to buffer

    assert(bytesAccessed == count); //will throw error if it reads back less bytes than requested
}

int mftSizeInBytes(VolumeHeader * volumeheader) {
    uint8_t mftSize = volumeheader->mftSize;
    printf("[-] MFT Size Value: %d\n", mftSize);
    if (mftSize > 255) {
        printf("[!] MFTSize is over 255. This is invalid\n");
        throw;
    }
    else if (mftSize <= 128) {
        printf("[-] MFTSize is under 128. Treating as number of clusters\n");
        uint64_t bytesPerCluster = volumeheader->bytesPerSector * volumeheader->sectorsPerCluster;
        int mftSizeInBytes = bytesPerCluster * mftSize;
        printf("[-] Returning file record size of %d bytes\n", mftSizeInBytes);
        return mftSizeInBytes;
    }
    else if (mftSize > 128) {
        int mftSizeInBytes = (int)pow(2.0, (256 - (int)mftSize));
        printf("[-] MFTSize is over 128. Treating as 2 ^ (256 - mftSize)\n");
        printf("[-] Returning file record size of %d bytes\n", mftSizeInBytes);
        return mftSizeInBytes;
    }
    return 0;
}




int main() {
    HANDLE drive = CreateFileA("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); //get handle to C drive
    if (drive) {
        printf("Got handle to C drive\n");
    }
    else {
        setColour(FOREGROUND_RED);
        printf("Could't get handle to C drive\n");
        setColour(FOREGROUND_WHITE);
        return -1;
        
    };


    VolumeHeader volumeheader;
    if (ReadToBuffer(drive, &volumeheader, 0, 512)) {
        printf("[+] Read volume header successfully\n");
        printf("[-] Volume system signature is: %s\n", volumeheader.VolumeSystemSignature);
        HANDLE volumeheader_cache = CreateFileA(".\\volume_header.bin", GENERIC_WRITE | GENERIC_READ , FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
        WriteFile(volumeheader_cache, &volumeheader, sizeof(volumeheader), NULL, NULL);
        volumeheader_cache = NULL;
    }
    else {
        setColour(FOREGROUND_RED);
        printf("[!] Failed to read volume header\n");
        setColour(FOREGROUND_WHITE);
        return -1;
        
    }

    
    
    
    printf("[-] Bytes per sector: %d\n", volumeheader.bytesPerSector);
    printf("[-] Sectors per cluster: %d\n", volumeheader.sectorsPerCluster);

    uint64_t bytesPerCluster = volumeheader.bytesPerSector * volumeheader.sectorsPerCluster;
    printf("[-] Calculated %d bytes per cluster\n", bytesPerCluster);

    //size of MFT file entry can 
    int mft_file_entry_size = mftSizeInBytes(&volumeheader);
    
    //we have to use malloc to dynamically create a buffer of the correct size
    //the MFT file size is always 1024 bytes but we want to calculate it just for our understanding of NTFS
    printf("[-] Allocating %d bytes for our first MFT file entry\n", mft_file_entry_size);
    

    uint8_t mftFile[1024];
    
    
    //multiply mft cluster number by bytes per cluster to get the file offset (in bytes)
    //volumeheader.mftClusterBlockNumber * bytesPerCluster
    //this is where we want to read from
    
    if (ReadToBuffer(drive, &mftFile, volumeheader.mftClusterBlockNumber * bytesPerCluster, mft_file_entry_size)) { 
        printf("[+] Read first MFT file entry successfully\n");
        HANDLE mft_first_file_cache = CreateFileA(".\\mft_first.bin", GENERIC_WRITE | GENERIC_READ , FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
        WriteFile(mft_first_file_cache, mftFile, mft_file_entry_size, NULL, NULL);
        mft_first_file_cache = NULL;
    }
    else {
        printf("[!] Failed to read first MFT file entry\n");
        return -1;
    }

    MFTEntry *mftFirstFile = (MFTEntry *) mftFile;

    if (strcmp(mftFirstFile->signature, "FILE")) {
        printf("[+] Signature of the first file entry is: %.4s\n", mftFirstFile->signature);
    }
    else {
        printf("[!] Something is wrong, reading first file entry signature as: %.4s\n", mftFirstFile->signature);
    }
    
    
    //check that we can parse flag enums
    printf("[-] Checking if has MFT_RECORD_IN_USE flag: %d\n", (mftFirstFile->entryFlags & MFTEntryFlags::MFT_RECORD_IN_USE));
    printf("[-] Checking if has MFT_RECORD_IS_DIRECTORY flag: %d\n", (mftFirstFile->entryFlags & MFTEntryFlags::MFT_RECORD_IS_DIRECTORY));
    printf("[-] Grabbing first attribute at offset of %i\n", mftFirstFile->attributesOffset);
    
    MFTAttributeHeader *attribute = (MFTAttributeHeader *) (mftFile + mftFirstFile->attributesOffset);



    //we can assume non resident is true because the entire MFT cannot fit inside a single MFT record
    //but if we didn't want to assume that, we could check that mftFirstFile->nonResidentFlag was 1
    NonResidentAttributeHeader *dataAttribute = nullptr;

    while (true) {
        printf("[-] Current attribute type is: %d\n", attribute->attributeType);
        printf("[-] Current attribute size as: %d\n", attribute->size);
        if (attribute->attributeType == 0x80) { //0x80 is $DATA
            dataAttribute = (NonResidentAttributeHeader *) attribute;
        } else if (attribute->attributeType == 0xFFFFFFFF) {
            printf("[!] Have hit value 0xFFFFFFFF. Reached end of attributes\n\n", attribute->attributeType);
            break;
        }

    
    HANDLE data_attribute_cache = CreateFileA(".\\data_attribute.bin", GENERIC_WRITE | GENERIC_READ , FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    WriteFile(data_attribute_cache, dataAttribute, sizeof(NonResidentAttributeHeader), 0, 0);

    //advance by the length of current attribute, i.e. go to the next attribute
    printf("[-] Advancing %d bytes\n", attribute->size);
    attribute = (MFTAttributeHeader *) ((int)attribute + attribute->size);
    //after this loop, dataAttribute is now storing the nonResidentAttribute header of our $DATA attribute
    }

    assert(dataAttribute);
    printf("[+] Located $DATA attribute of the MFT file\n", dataAttribute->attributeType);

    
    RunHeader * dataRun = (RunHeader *) ((int)(dataAttribute) + dataAttribute->dataRunsOffset);
    
}
