#include <iostream>
#include <limits.h>
#include <unistd.h>
#include "../include/TracedProcess.hpp"

int main(int argc, char* argv[])
{	
	LibraryInjector::TracedProcess* proc;
	char * p = NULL;
	if(argc != 3)
	{
		std::cerr << "Usage : " << argv[0] << " <process name or PID> <library name>" << std::endl;
		return 1;
	}
	char library_path[PATH_MAX];
	if(realpath(argv[2], library_path) == NULL || access(library_path, F_OK) == -1)
	{
		std::cerr << "[-] Library file " << argv[2] << " not found" << std::endl;
		return 1;
	}
	std::string process_name = std::string(argv[1]);
	std::string library_name = std::string(library_path);

	unsigned long converted = strtoul(argv[1], &p, 10);
	if (*p) 
	{
		proc = LibraryInjector::AttachByName(process_name);
	}
	else 
	{
		proc = LibraryInjector::AttachByPID(converted);
	}
	if(proc == NULL) 
	{ 
		std::cerr << "[-] Process " << process_name << " not found" << std::endl;
		return 1; 
	}
	std::cout << "[+] PID : " << proc->getPID() << std::endl;
	if(proc->LoadLibrary(library_name) == -1)
	{
			std::cerr << "[-] Failed to inject " << library_name << " in " << process_name << std::endl;
			delete proc;
			return 1; 
	}
	std::cout << "[+] Successfully injected " << library_name << " in " << process_name << std::endl;
	delete proc;
	return 0;
}

