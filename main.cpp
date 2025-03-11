#include <iostream>
#include <windows.h>
#include <string>

bool CloneDisk(int sourceIndex, int targetIndex) {
    std::string sourcePath = "\\\\.\\PhsicalDrive" + std::to_string(sourceIndex);
	std::string targetPath = "\\\\.\\PhsicalDrive" + std::to_string(targetIndex);

	HANDLE hSource = CreateFileA(sourcePath.c_str(),
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
    HANDLE hTarget = CreateFileA(targetPath.c_str(),\
        GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hSource == INVALID_HANDLE_VALUE || hTarget == INVALID_HANDLE_VALUE) {
        std::cerr << "[ERROR] Failed to open source or target disk." << std::endl;
        return false;
    }

    DISK_GEOMETRY dg;
    DWORD bytesReturned;
    if (!DeviceIoControl(hSource, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &dg, sizeof(dg), &bytesReturned, NULL)) {
        std::cerr << "[ERROR] Failed to get source disk geometry." << std::endl;
        CloseHandle(hSource);
        CloseHandle(hTarget);
        return false;
    }
    ULONGLONG totalSize = dg.Cylinders.QuadPart * dg.TracksPerCylinder * dg.SectorsPerTrack * dg.BytesPerSector;
    DWORD secotrSize = dg.BytesPerSector;

    const DWORD bufferSize = 1024 * 1024;
    BYTE* buffer = new BYTE[bufferSize];
    ULONGLONG totalCopied = 0;

    std::cout << "[INFO] Start cloning..." << std::endl;
	std::cout << "[INFO] Total size: " << totalSize / (1024 * 1024 * 1024) << " GB" << std::endl;

    DWORD bytesRead, bytesWritten;
    BOOL readResult, writeResult;

    while (totalCopied < totalSize) {
        DWORD toRead = bufferSize;
        if (totalCopied + bufferSize > totalSize) {
            toRead = (DWORD)(totalSize - totalCopied);
        }

        readResult = ReadFile(hSource, buffer, toRead, &bytesRead, NULL);
        if (!readResult || bytesRead == 0) {
            std::cerr << "[ERROR] Failed to read source disk." << std::endl;
            break;
        }

		writeResult = WriteFile(hTarget, buffer, bytesRead, &bytesWritten, NULL);
        if (!writeResult || bytesWritten != bytesRead) {
            std::cerr << "[ERROR] Failed to write target disk." << std::endl;
            break;
        }

        totalCopied += bytesRead;

        int percet = (int)((totalCopied * 100) / totalSize);
        std::cout << "\rProgress: " << percet << "% compeleted." << std::endl;
    }

    std::cout << "\n[INFO] Cloning completed." << std::endl;

    delete[] buffer;
    CloseHandle(hSource);
    CloseHandle(hTarget);
    return true;
}

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

    int sourceIndex, targetIndex;

    std::cout << "(Enter 'EXIT' to exit)" << std::endl;
    std::cout << "Enter source disk index (e.g., 0): ";
    std::cin >> sourceIndex;
    std::cout << "Enter target disk index (e.g., 1): ";
    std::cin >> targetIndex;

    std::cout << "[WARNING] All data on target disk will be destroyed !";
    std::cout << "Type 'YES' to confirm: " << std::endl;
    std::string confirm;
    std::cin >> confirm;
    if (confirm != "YES") {
        std::cout << "operation canceled." << std::endl;
        return 0;
    }

    if (confirm == "EXIT") {
        std::cout << "Exiting..." << std::endl;
        return 0;
    }

    if (!CloneDisk(sourceIndex, targetIndex)) {
        std::cerr << "[ERROR] Cloning failed." << std::endl;
        return 1;
    }

    return 0;
}
