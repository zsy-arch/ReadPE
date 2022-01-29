#pragma warning(disable: 4996)
#include <cstdio>
#include <cstring>
#include <Windows.h>
#include <vector>
#include <cmath>

#define LOG_ERROR(x) {printf("ERROR: %s\n", x);}

#if defined(_WIN64)
#define NT_HEADER_TYPE IMAGE_NT_HEADERS64
#elif defined(_WIN32)
#define NT_HEADER_TYPE IMAGE_NT_HEADERS32
#endif

struct RvaFoa {
	char* Name;
	DWORD MemSA;
	DWORD MemSize;
	DWORD FileSA;
	DWORD FileSize;
};
typedef struct RvaFoa RvaFoa;

HANDLE hFile = INVALID_HANDLE_VALUE;
char* filename = nullptr;
bool opt_rva = false;
RvaFoa* headers;
IMAGE_DOS_HEADER pe_dh;
NT_HEADER_TYPE pe_nth;
IMAGE_SECTION_HEADER* pe_sech;
DWORD num_read;
WORD num_sections;

DWORD calc_alignment(DWORD size, DWORD alignment);
DWORD rva2foa(DWORD rva, RvaFoa* headers, WORD size);
DWORD hex2int(char* str);
void show_sections(RvaFoa* headers, WORD size);

int main(const int argc, const char* argv[])
{
	if (argc < 2)
	{
		printf("Usage: readpe FILE_NAME\n");
		return 0;
	}

	for (int i = 1; i < argc; i++)
	{
		if (!stricmp("/rva", argv[i]))
		{
			opt_rva = true;
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
	headers[0].MemSA = pe_nth.OptionalHeader.ImageBase;
	headers[0].MemSize = calc_alignment(pe_nth.OptionalHeader.SizeOfHeaders, pe_nth.OptionalHeader.SectionAlignment);

	for (WORD i = 0; i < num_sections; i++)
	{
		headers[i + 1].Name = new char[16];
		memcpy(headers[i + 1].Name, &(pe_sech[i].Name), 8);
		headers[i + 1].Name[8] = 0;
		headers[i + 1].FileSA = headers[i].FileSA + headers[i].FileSize;
		headers[i + 1].FileSize = calc_alignment(pe_sech[i].SizeOfRawData, pe_nth.OptionalHeader.FileAlignment);
		headers[i + 1].MemSA = pe_nth.OptionalHeader.ImageBase + pe_sech[i].VirtualAddress;
		headers[i + 1].MemSize = calc_alignment(pe_sech[i].SizeOfRawData, pe_nth.OptionalHeader.SectionAlignment);
		/*if (headers[i].MemSize == 0)
		{
			headers[i].MemSize = headers[i + 1].MemSA - headers[i].MemSA;
		}*/
	}

	show_sections(headers, num_sections + 1);

	if (opt_rva)
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
				show_sections(headers, num_sections + 1);
				continue;
			}

			DWORD hex = hex2int(tmp);
			if (hex)
			{
				if (hex >= pe_nth.OptionalHeader.ImageBase)
				{
					printf("RVA: 0x%x, FOA: 0x%x\n",
						hex,
						rva2foa(hex , headers, num_sections + 1)
					);

				}
				else
				{
					printf("RVA: 0x%x, FOA: 0x%x\n",
						hex + pe_nth.OptionalHeader.ImageBase,
						rva2foa(hex + pe_nth.OptionalHeader.ImageBase, headers, num_sections + 1)
					);
				}
			}
			else break;
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

DWORD rva2foa(DWORD rva, RvaFoa* headers, WORD size)
{
	for (WORD i = 0; i < size; i++)
	{
		if (rva >= headers[i].MemSA && rva < headers[i].MemSA + headers[i].MemSize)
		{
			return headers[i].FileSA + (rva - headers[i].MemSA);
		}
	}
	return 0xffffffff;
}

DWORD hex2int(char* str)
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

void show_sections(RvaFoa* headers, WORD size)
{
	for (WORD i = 0; i < size; i++)
	{
		printf("[Section %s]\n", headers[i].Name);
		printf("\tFile SA: 0x%x, Size: 0x%x\n\tMem SA: 0x%x, Size: 0x%x\n",
			headers[i].FileSA,
			headers[i].FileSize,
			headers[i].MemSA,
			headers[i].MemSize
		);
	}
}