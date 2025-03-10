#include <iostream>
#include <windows.h>
#include <string>

bool IsRunAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

void ListPhysicalDrives() {
    std::cout << "Available physical drives:" << std::endl;
    for (int i = 0; i < 16; i++) {
        std::string diskPath = "\\\\.\\PhysicalDrive" + std::to_string(i);
        HANDLE hDevice = CreateFileA(
            diskPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hDevice != INVALID_HANDLE_VALUE) {
            DISK_GEOMETRY dg;
            DWORD bytesReturned;
            if (DeviceIoControl(
                hDevice,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                NULL,
                0,
                &dg,
                sizeof(dg),
                &bytesReturned,
                NULL
            )) {
                ULONGLONG diskSize = dg.Cylinders.QuadPart * dg.TracksPerCylinder * dg.SectorsPerTrack * dg.BytesPerSector;
                std::cout << "Disk " << i << ":" << std::endl;
                std::cout << "  - Total size: " << diskSize / (1024 * 1024 * 1024) << " GB" << std::endl;
                std::cout << "  - Sector size: " << dg.BytesPerSector << " Bytes" << std::endl;
            }
            else {
                std::cerr << "Failed to get geometry for disk " << i << "." << std::endl;
            }
            CloseHandle(hDevice);
        }
        else {
            DWORD err = GetLastError();
            std::cerr << "Failed to open disk " << i << ", Error code: " << err << std::endl;
        }
    }
}

void GetDiskInfo(int diskIndex) {
    std::string diskPath = "\\\\.\\PhysicalDrive" + std::to_string(diskIndex);
    HANDLE hDevice = CreateFileA(
        diskPath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open disk " << diskIndex << "." << std::endl;
        return;
    }

    DISK_GEOMETRY dg;
    DWORD bytesReturned;
    if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytesReturned, NULL)) {
        ULONGLONG diskSize = dg.Cylinders.QuadPart * dg.TracksPerCylinder * dg.SectorsPerTrack * dg.BytesPerSector;
        std::cout << "Information for disk " << diskIndex << ":" << std::endl;
        std::cout << "  - Total size: " << diskSize / (1024 * 1024 * 1024) << " GB" << std::endl;
        std::cout << "  - Sector size: " << dg.BytesPerSector << " Bytes" << std::endl;
    }
    else {
        std::cerr << "Failed to get disk " << diskIndex << " information." << std::endl;
    }

    CloseHandle(hDevice);
}

int main() {
    if (!IsRunAsAdmin()) {
        std::cerr << "[ERROR] Please run this program as administator !" << std::endl;
        system("pause");
        return 1;
    }

    ListPhysicalDrives();

    int diskIndex;
    std::cout << "\nEnter the physical disk index you want to view (e.g., 0 for the first disk): ";
    std::cin >> diskIndex;

    GetDiskInfo(diskIndex);

    return 0;
}
