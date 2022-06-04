#include "windows.h"

// this came from guided hacking

typedef HINSTANCE(WINAPI* a)(char* lpLibFilename);
typedef UINT_PTR(WINAPI* b)(HINSTANCE hModule, char* lpProcName);
typedef BOOL(WINAPI* c)(void * hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
	void*		pLoadLibraryA;
	void*	pGetProcAddress;
	HINSTANCE			hMod;
};

#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)

void __stdcall shellcode_m(struct MANUAL_MAPPING_DATA * pData) {
	if (!pData)
		return;

	BYTE * pBase = (BYTE*)(pData);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)(pData);
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pBase + dos->e_lfanew);
	IMAGE_OPTIONAL_HEADER32* pOpt = &nt->OptionalHeader;

	a _LoadLibraryA = (a)pData->pLoadLibraryA;
	b _GetProcAddress = (b)pData->pGetProcAddress;
	c _DllMain = (c)(pBase + pOpt->AddressOfEntryPoint);

	BYTE * LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		IMAGE_BASE_RELOCATION * pRelocData = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress) {
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD * pRelativeInfo = (WORD*)(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
				if (RELOC_FLAG(*pRelativeInfo)) {
					UINT_PTR * pPatch = (UINT_PTR*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += (UINT_PTR)(LocationDelta);
				}
			}
			pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		IMAGE_IMPORT_DESCRIPTOR * pImportDescr = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char * szMod = (char*)(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR * pThunkRef	= (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR * pFuncRef	= (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = _GetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
				}
				else {
					IMAGE_IMPORT_BY_NAME * pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		IMAGE_TLS_DIRECTORY* pTLS = (IMAGE_TLS_DIRECTORY*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK * pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, 0);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, 0);

	pData->hMod = (HINSTANCE)(pBase);
}
