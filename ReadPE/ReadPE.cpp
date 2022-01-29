#pragma warning(disable: 4996)
#include <cstdio>
#include <cstring>
#include <Windows.h>
#include <string>
#include <cmath>

#define LOG_ERROR(x) {printf("ERROR: %s\n", x);}

#if defined(_WIN64)
#define NT_HEADER_TYPE IMAGE_NT_HEADERS64
#elif defined(_WIN32)
#define NT_HEADER_TYPE IMAGE_NT_HEADERS32
#endif

#if defined(_WIN64)
#define ADDR_TYPE ULONGLONG
#define FMT_HEX "llx"
#elif defined(_WIN32)
#define ADDR_TYPE DWORD
#define FMT_HEX "x"
#endif

struct RvaFoa {
	char* Name;
	ADDR_TYPE MemSA;
	DWORD MemSize;
	ADDR_TYPE FileSA;
	DWORD FileSize;
};

typedef struct RvaFoa RvaFoa;
HANDLE hFile = INVALID_HANDLE_VALUE;
char* filename = nullptr;
bool opt_interactive = false;
RvaFoa* headers;
IMAGE_DOS_HEADER pe_dh;
NT_HEADER_TYPE pe_nth;
IMAGE_SECTION_HEADER* pe_sech;
DWORD num_read;
WORD num_sections;

DWORD calc_alignment(DWORD size, DWORD alignment);
ADDR_TYPE rva2foa(ADDR_TYPE rva);
ADDR_TYPE hex2int(char* str);
VOID show_sections();
VOID show_iat();
LPVOID ReadBytesFromFile(ADDR_TYPE foa, DWORD size);
LPCSTR ReadStringFromFile(ADDR_TYPE foa);

int main(const int argc, const char* argv[])
{
	if (argc < 2)
	{
		printf("Usage: readpe FILE_NAME\n");
		return 0;
	}

	for (int i = 1; i < argc; i++)
	{
		if (!stricmp("/i", argv[i]))
		{
			opt_interactive = true;
		}
		else
		{
			filename = new char[strlen(argv[i])];
			strcpy(filename, argv[i]);
			hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		}
	}

	if (hFile == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("cannot open file");
		return 0;
	}

	printf("PE file: %s\n", filename);
	ReadFile(hFile, &pe_dh, sizeof(IMAGE_DOS_HEADER), &num_read, NULL);
	if (num_read != sizeof(IMAGE_DOS_HEADER))
	{
		LOG_ERROR("cannot read file");
		return 0;
	}
	if (pe_dh.e_magic != 0x5A4D)
	{
		LOG_ERROR("illegal magic");
		return 0;
	}

	SetFilePointer(hFile, pe_dh.e_lfanew, NULL, FILE_BEGIN);
	ReadFile(hFile, &pe_nth, sizeof(NT_HEADER_TYPE), &num_read, NULL);
	if (num_read != sizeof(NT_HEADER_TYPE))
	{
		LOG_ERROR("cannot read file");
		return 0;
	}
	if (pe_nth.Signature != 0x00004550)
	{
		LOG_ERROR("illegal magic");
		return 0;
	}

	num_sections = pe_nth.FileHeader.NumberOfSections;
	pe_sech = new IMAGE_SECTION_HEADER[num_sections];
	SetFilePointer(hFile, pe_dh.e_lfanew + sizeof(NT_HEADER_TYPE), NULL, FILE_BEGIN);
	ReadFile(hFile, pe_sech, num_sections * sizeof(IMAGE_SECTION_HEADER), &num_read, NULL);
	if ((num_sections * sizeof(IMAGE_SECTION_HEADER)) != num_read)
	{
		LOG_ERROR("cannot read file");
		return 0;
	}

	headers = new RvaFoa[num_sections + 1];
	headers[0].Name = new char[16];
	strcpy(headers[0].Name, "peheader");
	headers[0].FileSA = 0;
	headers[0].FileSize = calc_alignment(pe_nth.OptionalHeader.SizeOfHeaders, pe_nth.OptionalHeader.FileAlignment);
	headers[0].MemSA = 0;
	headers[0].MemSize = calc_alignment(pe_nth.OptionalHeader.SizeOfHeaders, pe_nth.OptionalHeader.SectionAlignment);

	for (WORD i = 0; i < num_sections; i++)
	{
		headers[i + 1].Name = new char[16];
		memcpy(headers[i + 1].Name, &(pe_sech[i].Name), 8);
		headers[i + 1].Name[8] = 0;
		headers[i + 1].FileSA = headers[i].FileSA + headers[i].FileSize;
		headers[i + 1].FileSize = calc_alignment(pe_sech[i].SizeOfRawData, pe_nth.OptionalHeader.FileAlignment);
		headers[i + 1].MemSA = pe_sech[i].VirtualAddress;
		headers[i + 1].MemSize = calc_alignment(pe_sech[i].SizeOfRawData, pe_nth.OptionalHeader.SectionAlignment);
	}

	show_sections();

	if (opt_interactive)
	{
		while (true)
		{
			printf("> ");
			char* tmp = new char[16];
			scanf("%s", tmp);
			if (!strcmp(tmp, "cls"))
			{
				system("cls");
				continue;
			}
			else if (!strcmp(tmp, "s"))
			{
				show_sections();
				continue;
			}
			else if (!strcmp(tmp, "iat"))
			{
				show_iat();
			}
			else if (!strcmp(tmp, "rva"))
			{
				scanf("%s", tmp);
				ADDR_TYPE hex = hex2int(tmp);
				if (hex)
				{
					printf("RVA: 0x%" FMT_HEX ", FOA: 0x%" FMT_HEX "\n",
						hex,
						rva2foa(hex)
					);
				}
				continue;
			}


		}
	}
	return 0;
}

DWORD calc_alignment(DWORD size, DWORD alignment)
{
	DWORD i = 0;
	while (size > i * alignment) i++;
	return i * alignment;
}

ADDR_TYPE rva2foa(ADDR_TYPE rva)
{
	for (WORD i = 0; i < num_sections + 1; i++)
	{
		if (rva >= headers[i].MemSA && rva < headers[i].MemSA + headers[i].MemSize)
		{
			return headers[i].FileSA + (rva - headers[i].MemSA);
		}
	}
	return 0xffffffff;
}

ADDR_TYPE hex2int(char* str)
{
	DWORD result = 0;
	int bound = 0;
	int len = strlen(str);
	int j = 0;
	if (len > 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
	{
		bound = 2;
	}
	for (int i = len - 1; i >= bound; i--)
	{
		if (str[i] >= '0' && str[i] <= '9')
		{
			result += (str[i] - '0') * pow(16, j);
		}
		else if (str[i] >= 'a' && str[i] <= 'f')
		{
			result += (str[i] - 'a' + 10) * pow(16, j);
		}
		else if (str[i] >= 'A' && str[i] <= 'F')
		{
			result += (str[i] - 'A' + 10) * pow(16, j);
		}
		else
		{
			result = 0;
			printf("ERROR: %c\n", str[i]);
			break;
		}
		j++;
	}
	return result;
}

VOID show_sections()
{
	for (WORD i = 0; i < num_sections + 1; i++)
	{
		printf("[Section %s]\n", headers[i].Name);
		printf("\tFile SA: 0x%" FMT_HEX ", Size: 0x%x""\n\tMem SA: 0x%" FMT_HEX ", Size: 0x%x""\n",
			headers[i].FileSA,
			headers[i].FileSize,
			headers[i].MemSA,
			headers[i].MemSize
		);
	}
}

VOID show_iat()
{
	ADDR_TYPE dwIatRva = pe_nth.OptionalHeader.DataDirectory[1].VirtualAddress;
	DWORD dwIatSize = pe_nth.OptionalHeader.DataDirectory[1].Size;
	ADDR_TYPE dwIatFoa = rva2foa(dwIatRva);
	DWORD dwIatLen = dwIatSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	printf("IAT SA: 0x%" FMT_HEX ", FOA: 0x%" FMT_HEX "\n", dwIatRva, dwIatFoa);
	SetFilePointer(hFile, dwIatFoa, NULL, FILE_BEGIN);
	LPVOID lpvBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwIatSize);
	ReadFile(hFile, lpvBuf, dwIatSize, &num_read, NULL);
	if (num_read != dwIatSize)
	{
		printf("ERROR: cannot read iat\n");
		return;
	}
	PIMAGE_IMPORT_DESCRIPTOR pe_iat = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(lpvBuf);
	for (DWORD i = 0; i < dwIatLen; i++)
	{
		LPCSTR name = ReadStringFromFile(rva2foa(pe_iat[i].Name));
		if (name == NULL) continue;
		ADDR_TYPE pe_int_list_foa = rva2foa(pe_iat[i].OriginalFirstThunk);
		printf("DLL Name: %s\n", name);
		printf("INT FOA: 0x%" FMT_HEX "\n", pe_int_list_foa);
		ADDR_TYPE start = pe_int_list_foa;
		DWORD block_size = sizeof(ADDR_TYPE);
		while (true)
		{
			ADDR_TYPE iin_rva = *reinterpret_cast<ADDR_TYPE*>(ReadBytesFromFile(start, block_size));
			if (iin_rva == 0) break;
			ADDR_TYPE iin_foa = rva2foa(iin_rva);
			ADDR_TYPE proc_name_foa = iin_foa + 2;
			LPCSTR proc_name = ReadStringFromFile(proc_name_foa);
			printf("\t%s [FOA: 0x%" FMT_HEX "]\n", proc_name, proc_name_foa);
			start += block_size;
		}
	}
}

LPCSTR ReadStringFromFile(ADDR_TYPE foa)
{
	if (foa == 0) return NULL;
	CHAR tmp;
	SetFilePointer(hFile, foa, NULL, FILE_BEGIN);
	std::string str;
	while (1)
	{
		ReadFile(hFile, &tmp, sizeof(tmp), &num_read, NULL);
		if (num_read == 0 || tmp == '\0') break;
		str += *reinterpret_cast<char*>(&tmp);
	}
	if (!str.empty())
	{
		CHAR* result = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, str.size() + 16);
		CopyMemory(result, str.c_str(), str.size());
		return result;
	}
	else
	{
		return NULL;
	}
}

LPVOID ReadBytesFromFile(ADDR_TYPE foa, DWORD size)
{
	if (foa == 0) return NULL;
	SetFilePointer(hFile, foa, NULL, FILE_BEGIN);
	LPVOID lpvBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
	ReadFile(hFile, lpvBuf, size, &num_read, NULL);
	if (num_read == 0) return NULL;
	return lpvBuf;
}