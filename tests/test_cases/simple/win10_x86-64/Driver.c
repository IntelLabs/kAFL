/*
 * Copyright 2019 Sergej Schumilo, Cornelius Aschermann
 *
 * SPDX-License-Identifier: MIT
 */

#include <ntddk.h>

#define DEVICE_NAME         L"\\Device\\testKafl"
#define DOS_DEVICE_NAME     L"\\DosDevices\\testKafl"
#define IOCTL_KAFL_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

NTSTATUS crashMe(IN PIO_STACK_LOCATION IrpStack){
    SIZE_T size = 0;
    PCHAR userBuffer = NULL;

    userBuffer = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
    size = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (size < 0xe){
        return STATUS_SUCCESS;
    }

    if (userBuffer[0] == 'P'){
        if (userBuffer[1] == 'w'){
            if (userBuffer[2] == 'n'){
                if (userBuffer[3] == 'T'){
                    if (userBuffer[4] == 'o'){
                        if (userBuffer[5] == 'w'){
                            if (userBuffer[6] == 'n'){
                            DbgPrint("[+] KAFL vuln drv -- SETEIP");
                            /* hell yeah */
                            ((VOID(*)())0x0)();
                            }
                        }
                    }
                }
            }
        }
    }

    if (userBuffer[0] == 'w'){
        DbgPrint("[+] KAFL vuln drv -- ONE");
        if (userBuffer[1] == '0'){
            DbgPrint("[+] KAFL vuln drv -- TWO");
            if (userBuffer[2] == '0'){
                DbgPrint("[+] KAFL vuln drv -- THREE");
                if (userBuffer[3] == 't'){
                    DbgPrint("[+] KAFL vuln drv -- CRASH");
                    size = *((PSIZE_T)(0x0));
                }
            }
        }
    }

    return STATUS_SUCCESS;
}


NTSTATUS handleIrp(IN PDEVICE_OBJECT DeviceObj, IN PIRP pIrp){
	PIO_STACK_LOCATION	irpStack = 0;
	ULONG				ioctl;

	irpStack = IoGetCurrentIrpStackLocation(pIrp);

    pIrp->IoStatus.Information = 0;
    pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(DeviceObj);
    PAGED_CODE();

    switch(irpStack->MajorFunction){
        case IRP_MJ_DEVICE_CONTROL:
            ioctl = irpStack->Parameters.DeviceIoControl.IoControlCode;
            switch(ioctl){
                case IOCTL_KAFL_INPUT:
                    DbgPrint("[+] KAFL vuln drv -- crash attempt\n");
                    pIrp->IoStatus.Status = crashMe(irpStack);
                    break;
                default:
                    pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    break;
            }
            break;
        case IRP_MJ_CREATE:
        case IRP_MJ_CLOSE:
            pIrp->IoStatus.Status = STATUS_SUCCESS;
            break;
    };

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return pIrp->IoStatus.Status;
}


void DriverUnload(PDRIVER_OBJECT pDriverObject){
    UNICODE_STRING dosDeviceName = { 0 };
    RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(pDriverObject->DeviceObject);
    DbgPrint("[+] KAFL vuln drv -- unloaded");
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObj, IN PUNICODE_STRING RegPath){
    UINT32          i = 0;
    NTSTATUS        ntstatus;
    PDEVICE_OBJECT  deviceObject = NULL;
    UNICODE_STRING  deviceName, dosDeviceName = { 0 };

    UNREFERENCED_PARAMETER(RegPath);
    PAGED_CODE();

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);

    ntstatus = IoCreateDevice(DriverObj, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if(!NT_SUCCESS(ntstatus)){
        DbgPrint("[-] KAFL vuln drv -- IoCreateDevice failed: 0x%X\n", ntstatus);
        IoDeleteDevice(DriverObj->DeviceObject);
        return ntstatus;
    }

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++){
        DriverObj->MajorFunction[i] = handleIrp;
    }

    DriverObj->DriverUnload = DriverUnload;
    deviceObject->Flags |= DO_DIRECT_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    ntstatus = IoCreateSymbolicLink(&dosDeviceName, &deviceName);

    DbgPrint("[+] KAFL vuln drv -- loaded");
    return ntstatus;
}

