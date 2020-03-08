#include <sys/types.h>
#include <stdarg.h>
#include <sys/user.h>
#include <string>
#include <map>

namespace LibraryInjector
{
	class TracedProcess
	{
		private:
			pid_t pid;
			void* malloc_addr;
			void* free_addr;
			void* dlopen_addr;
			void* linker_base_addr;
			void* libc_base_addr;
			bool ResumeExec();
			bool PauseExec();
			bool IsPausedInRestartableSyscall();
			bool PushToStack(struct user_regs_struct* regs, unsigned long data);
			void* CallFunctionAt(void* function_address, unsigned int n_args, ...);
			bool WriteMemory(void* write_addr, void* data, int size);
			void SingleStep(unsigned long nb, bool infinite);
			void PrintStack(unsigned long nb);
			bool IsPaused();
			void PrintRegisters();

		public:
			TracedProcess(pid_t _pid);
			pid_t getPID();
			int LoadLibrary(std::string library_name);
			~TracedProcess();
	};
	TracedProcess* AttachByName(std::string process_name);
	TracedProcess* AttachByPID(pid_t pid);
}
