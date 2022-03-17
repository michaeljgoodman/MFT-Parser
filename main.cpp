#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <cmath>

using namespace std;

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
#pragma pack(pop)


#pragma pack(push,1)
struct MFTEntry {
    uint16_t fixupValuesOffset;
    uint16_t numberOfFixupValues;
    uint64_t metadataTransactionSequenceNumber;
    uint16_t sequence;
    uint16_t linkCount;
    uint16_t attributesOffset;
    uint16_t entryFlags;
    uint32_t usedEntrySize;
    uint32_t totalEntrySize;
    uint64_t baseRecordFileReference;
    uint16_t firstAttributeIdentifier;
    uint8_t ignore[8];
    uint32_t index;

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
    printf("MFT Size Value: %d\n", mftSize);
    if (mftSize > 255) {
        cout << "MFTSize is over 255. This is invalid" << endl;
        throw;
    }
    else if (mftSize <= 128) {
        printf("MFTSize is under 128. Treating as number of clusters\n");
        uint64_t bytesPerCluster = volumeheader->bytesPerSector * volumeheader->sectorsPerCluster;
        int mftSizeInBytes = bytesPerCluster * mftSize;
        printf("Returning file record size of %d bytes\n", mftSizeInBytes);
        return mftSizeInBytes;
    }
    else if (mftSize > 128) {
        int mftSizeInBytes = (int)pow(2.0, (256 - (int)mftSize));
        printf("MFTSize is over 128. Treating as 2 ^ (256 - mftSize)\n");
        printf("Returning file record size of %d bytes\n", mftSizeInBytes);
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
        printf("Could't get handle to C drive\n");
        return -1;
    };


    VolumeHeader volumeheader;
    if (ReadToBuffer(drive, &volumeheader, 0, 512)) {
        printf("Read volume header successfully\n");
        printf("Volume system signature is: %s\n", volumeheader.VolumeSystemSignature);
    }
    else {
        cout << "Failed to read volume header" << endl;
        return -1;
    }

    
    HANDLE volumeheader_cache = CreateFileA(".\\volume_header.bin", GENERIC_WRITE | GENERIC_READ , FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    WriteFile(volumeheader_cache, &volumeheader, sizeof(volumeheader), NULL, NULL);

    
    printf("Bytes per sector: %d\n", volumeheader.bytesPerSector);
    printf("Sectors per cluster: %d\n", volumeheader.sectorsPerCluster);

    uint64_t bytesPerCluster = volumeheader.bytesPerSector * volumeheader.sectorsPerCluster;
    printf("Calculated %d bytes per cluster\n", bytesPerCluster);

    //size of MFT file entry can 
    int mft_file_entry_size = mftSizeInBytes(&volumeheader);
    
    //we have to use malloc to dynamically create a buffer of the correct size
    //the MFT file size is always 1024 bytes but we want to calculate it just for our understanding of NTFS
    printf("Allocating %d bytes for our first MFT file entry\n", mft_file_entry_size);
    
    void *mftFirstFile = malloc(mft_file_entry_size);
    
    //multiply mft cluster number by bytes per cluster to get the file offset (in bytes)
    //volumeheader.mftClusterBlockNumber * bytesPerCluster
    //this is where we want to read from
    
    if (ReadToBuffer(drive, mftFirstFile, volumeheader.mftClusterBlockNumber * bytesPerCluster, mft_file_entry_size)) { 
        printf("Read first MFT file entry successfully\n");
        HANDLE mft_first_file_cache = CreateFileA(".\\mft_first.bin", GENERIC_WRITE | GENERIC_READ , FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
        WriteFile(mft_first_file_cache, mftFirstFile, mft_file_entry_size, NULL, NULL);
    }
    else {
        printf("Failed to read first MFT file entry\n");
        return -1;
    }

}