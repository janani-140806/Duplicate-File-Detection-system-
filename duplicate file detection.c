#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#define SAMPLE_SIZE 65536
#define MAX_FILES 10000
#define MAX_PATH_LEN 1024

uint64_t fnv1a_hash(char *data, size_t len) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    uint64_t prime = 0x100000001b3ULL;
    size_t i;

    for (i = 0; i < len; i++) {
        hash ^= (unsigned char)data[i];
        hash *= prime;
    }
    return hash;
}


typedef struct {
    char path[MAX_PATH_LEN];
    long long size;
    uint64_t hash;
} FileInfo;

FileInfo files[MAX_FILES];
int fileCount = 0;


uint64_t compute_file_hash(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return 0;

    char buffer = (char)malloc(SAMPLE_SIZE);
    if (!buffer) {
        fclose(fp);
        return 0;
    }

    size_t bytesRead = fread(buffer, 1, SAMPLE_SIZE, fp);
    uint64_t hash = fnv1a_hash(buffer, bytesRead);

    free(buffer);
    fclose(fp);
    return hash;
}

void scan_directory(const char *folderPath) {

    char searchPath[MAX_PATH_LEN];
    WIN32_FIND_DATAA data;
    HANDLE hFind;

    sprintf(searchPath, "%s\\*", folderPath);

    hFind = FindFirstFileA(searchPath, &data);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Folder not found!\n");
        return;
    }

    do {
        if (strcmp(data.cFileName, ".") == 0 || strcmp(data.cFileName, "..") == 0)
            continue;

        char fullPath[MAX_PATH_LEN];
        sprintf(fullPath, "%s\\%s", folderPath, data.cFileName);

        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_directory(fullPath);
        } else {
            if (fileCount < MAX_FILES) {
                strcpy(files[fileCount].path, fullPath);
                files[fileCount].size = data.nFileSizeLow;
                files[fileCount].hash = compute_file_hash(fullPath);
                fileCount++;
            }
        }

    } while (FindNextFileA(hFind, &data));

    FindClose(hFind);
}


void find_duplicates() {
    int found = 0;
    int i, j;

    printf("\n===== DUPLICATE FILES =====\n");

    for (i = 0; i < fileCount; i++) {
        for (j = i + 1; j < fileCount; j++) {

            if (files[i].size == files[j].size &&
                files[i].hash == files[j].hash) {

                found = 1;
                printf("\nDuplicate group:\n");
                printf("  %s\n", files[i].path);
                printf("  %s\n", files[j].path);
            }
        }
    }

    if (!found)
        printf("No duplicate files found.\n");
}


int main() {
    char directory[MAX_PATH_LEN];

    printf("Enter folder path to scan:\n");
    gets(directory);  

    scan_directory(directory);

    printf("\nTotal scanned files: %d\n", fileCount);

    find_duplicates();

    return 0;
}
