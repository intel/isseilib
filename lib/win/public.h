/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/
#ifndef ISSEI_PUBLIC_H_
#define ISSEI_PUBLIC_H_

//
// Define an Interface Guid so that applications can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_IsseiDriver,
    0xe6f5b28c,0x0da8,0x4c58,0xb6,0x73,0xc7,0x07,0x48,0xa0,0x2b,0x42);
// {e6f5b28c-0da8-4c58-b673-c70748a02b42}


#define FILE_DEVICE_ISSEI  0x8000

#define IOCTL_ISSEI_CONNECT_CLIENT \
    CTL_CODE(FILE_DEVICE_ISSEI, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)

#define IOCTL_ISSEI_DISCONNECT_CLIENT \
    CTL_CODE(FILE_DEVICE_ISSEI, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)

#define IOCTL_ISSEI_STATUS_INFORMATION \
    CTL_CODE(FILE_DEVICE_ISSEI, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)


#pragma pack(push, 1) 

typedef struct FW_CLIENT_ {
    uint32_t MaxMessageLength;
    uint8_t  ProtocolVersion;
    uint8_t  Reserved[3];
    uint32_t Flags;
} FW_CLIENT;

#pragma pack(pop)


typedef struct DRIVER_STATUS_INFORMATION_ {
    uint32_t DriverReady          : 1;    // 1 Ready
                                          // 0 Not Ready (Link reset flows was not completed)
    uint32_t LinkResetCounter     : 8;    // 
                                          
    
} DRIVER_STATUS_INFORMATION;


#endif