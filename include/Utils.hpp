#include <sys/types.h>
#include <sys/user.h>
#include <string>

namespace LibraryInjector
{
	namespace Utils
	{
		pid_t GetPIDFromProcessName(std::string proc_name);
		void * GetLibraryBaseAddress(std::string library_name, pid_t pid);
		std::string GetLibraryFullName(std::string library_name, pid_t pid);
	}
}
