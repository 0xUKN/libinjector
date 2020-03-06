#include <sys/types.h>
#include <string>
#include <dirent.h>
#include <sys/user.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <iostream>
#include <unistd.h>
#include <cstring>
#include "../include/Utils.hpp"

namespace LibraryInjector
{
	namespace Utils
	{
		pid_t GetPIDFromProcessName(std::string proc_name)
		{
			struct dirent* read_file = NULL;
			const char* process_name = proc_name.c_str();
			DIR* base_directory = NULL;
			char exe_path[200];
			char exe_name[200];
			int len_exe_name = 0;
			int i = 0;
			int pid = 0;
			base_directory = opendir("/proc/");
			if(base_directory == NULL)
			{ 
				perror("opendir");
				return -1; 
			}
			read_file = readdir(base_directory);
			while (read_file != NULL)
			{
				pid = strtol(read_file->d_name, NULL, 10);
				if(pid != 0)
				{
					snprintf(exe_path, sizeof(exe_path) - 1, "/proc/%d/exe", pid);
					len_exe_name = readlink(exe_path, exe_name, sizeof(exe_name) - 1);
					if(len_exe_name != -1)
					{
						exe_name[len_exe_name] = '\0';
						for(i = len_exe_name - 1; i > 0; i--)
						{
							if(exe_name[i] == '/')
							{
								break;
							}
						}
						if(strcmp(exe_name + i + 1, process_name) == 0)
						{
							return pid;
						}
					}
				}
				read_file = readdir(base_directory);
			}
			return -1;	
		}

		void * GetLibraryBaseAddress(std::string library_name, pid_t pid)
		{
			char maps_path[200];
			char maps_content[400];
			void * lib_ptr = NULL;
			FILE* fd = NULL;
			if(pid <= 0) { return NULL; }
			snprintf(maps_path, sizeof(maps_path) - 1, "/proc/%d/maps", pid);
			fd = fopen(maps_path, "r");
			if(fd == NULL) 
			{ 
				perror("open");
				return NULL; 
			}
			while(fgets(maps_content, sizeof(maps_content), fd))
			{
				if(strstr(maps_content, library_name.c_str()))
				{
					lib_ptr = (void *)strtoul(maps_content, NULL, 16);
					break;
				}
			}
			fclose(fd);
			return lib_ptr;
		}
	}
}
