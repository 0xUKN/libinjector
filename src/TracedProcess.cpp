#include <sys/ptrace.h>
#include <sys/types.h>
#include <signal.h>
#include <string>
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <sys/user.h>
#include "../include/TracedProcess.hpp"
#include <errno.h>
#include "../include/Utils.hpp"
#define LIBC "libc-2.29.so"
#define LINKER "libdl-2.29.so"
#define ALLOWED_TRIES 10
//#define DEBUG
//#define DEBUG_2

namespace LibraryInjector
{

	TracedProcess::TracedProcess(pid_t _pid)
	{
		int status = 0;
		if(_pid > 0 && ptrace(PTRACE_ATTACH, _pid, NULL, NULL) != -1 && waitpid(_pid, &status, WUNTRACED) && ptrace(PTRACE_SETOPTIONS, _pid, NULL, PTRACE_O_TRACESYSGOOD) != -1)
		{
			pid = _pid;
			libc_base_addr = Utils::GetLibraryBaseAddress(LIBC, pid);
			linker_base_addr = Utils::GetLibraryBaseAddress(LINKER, pid);
			void* local_libc_base_addr = Utils::GetLibraryBaseAddress(LIBC, getpid());
			void* local_linker_base_addr = Utils::GetLibraryBaseAddress(LINKER, getpid());
			void* local_malloc_addr = dlsym(dlopen(LIBC, RTLD_LAZY), "malloc");
			void* local_free_addr = dlsym(dlopen(LIBC, RTLD_LAZY), "free");
			void* local_dlopen_addr = dlsym(dlopen(LINKER, RTLD_LAZY), "dlopen");
			if(libc_base_addr == NULL || linker_base_addr == NULL || local_libc_base_addr == NULL || local_linker_base_addr == NULL)
			{
				throw std::runtime_error("Error: Could not found required library");
			}
			
			//Resolve ASLR
			malloc_addr = (void *)((unsigned long)local_malloc_addr - (unsigned long)local_libc_base_addr + (unsigned long)libc_base_addr);
			free_addr = (void *)((unsigned long)local_free_addr - (unsigned long)local_libc_base_addr + (unsigned long)libc_base_addr);
			dlopen_addr = (void *)((unsigned long)local_dlopen_addr - (unsigned long)local_linker_base_addr + (unsigned long)linker_base_addr);
			ResumeExec();
		}
		else
		{
			throw std::runtime_error("Error: Could not trace required process");
		}
	}

	pid_t TracedProcess::getPID()
	{
		return pid;
	}

	bool TracedProcess::ResumeExec()
	{
		if(!IsPaused())
		{
			return false;
		}
		if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
		{
			perror("ptrace");
			return false;
		}
		return true;
	}

	bool TracedProcess::PauseExec()
	{
		if(IsPaused())
		{
			return false;
		}
		int status = 0;
		siginfo_t sig;
		if(kill(pid, SIGINT) == -1)
		{
			perror("kill");
			return false;
		}
		while(true)
		{
			waitpid(pid, &status, WUNTRACED);
			if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGINT) 
			{
				if(ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig) == -1)
				{
					perror("ptrace");
					throw std::runtime_error("Error: Unknown error");
				}

				if(sig.si_signo == SIGINT && sig.si_pid == getpid()) 
				{
					ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
					waitpid(pid, &status, WUNTRACED);
					break;
				}
				else
				{
					ptrace(PTRACE_CONT, pid, NULL, NULL);
				}
			} 
			else if (WIFEXITED(status)) 
			{
				throw std::runtime_error("Error: Tracee exited");
			}
			else 
			{
				ptrace(PTRACE_CONT, pid, NULL, NULL);
			}
		}
		#ifdef DEBUG
		PrintRegisters();
		#endif
		return true;
	}
	
	bool TracedProcess::IsPaused()
	{
		struct user_regs_struct regs;
		long ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if(ret == -1 && errno == ESRCH)
		{
			return false;
		}
		else if(ret == -1)
		{
			perror("ptrace");
			return true;
		}
		return true;
	}

	bool TracedProcess::IsPausedInRestartableSyscall() //This function is useless since we always stop the process after a SYSCALL (PTRACE_SYSCALL in PauseExec())
	{
		unsigned long a;
		struct user_regs_struct regs;
		if(!IsPaused())
		{
			throw std::runtime_error("Error: Process is not paused");
		}
		if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		{
			perror("ptrace");
			return NULL;
		}
		a = ptrace(PTRACE_PEEKTEXT, pid, regs.rip-2, NULL);
		if(errno)
		{
			perror("ptrace");
			return false;
		}
		//restartable syscall triggers needs -2 offset
		//7 poll
		//35 nanosleep
		//230 clock_nanosleep
		//202 futex
		//0x050f => syscall
		//0x80cd => int 0x80
		a &= 0xffff;
		if(a == 0x050f || a == 0x80cd)
		{
			#ifdef DEBUG
			printf("SYSCALL NUMBER %lld\n", regs.orig_rax);
			#endif
			if(regs.orig_rax == 7 || regs.orig_rax == 35 || regs.orig_rax == 230 || regs.orig_rax == 202) { return true;}
		}
		return false;
	}

	void* TracedProcess::CallFunctionAt(void* function_address, unsigned int n_args,...)
	{
		struct user_regs_struct save_regs;
		bool wasPaused = true;
		struct user_regs_struct regs;
		bool inSyscall = false;
		void * return_value = NULL;
		va_list args;
		va_start(args, n_args);

		if(!IsPaused()) { PauseExec(); wasPaused = false;}
		if(ptrace(PTRACE_GETREGS, pid, NULL, &save_regs) == -1)
		{
			perror("ptrace");
			if(!wasPaused) { ResumeExec(); }
			return NULL;
		}

		memcpy(&regs, &save_regs, sizeof(struct user_regs_struct));
		#ifdef DEBUG
		PrintRegisters();
		PrintStack(4);
		#endif
		switch(n_args)
		{
			case 0: //NO ARG
				break;
			case 1: //RDI
				regs.rdi = va_arg(args, unsigned long);
				break;
			case 2: //RDI, RSI
				regs.rdi = va_arg(args, unsigned long);
				regs.rsi = va_arg(args, unsigned long);
				break;
			case 3: //RDI, RSI, RDX
				regs.rdi = va_arg(args, unsigned long);
				regs.rsi = va_arg(args, unsigned long);
				regs.rdx = va_arg(args, unsigned long);
				break;
			case 4: //RDI, RSI, RDX, RCX
				regs.rdi = va_arg(args, unsigned long);
				regs.rsi = va_arg(args, unsigned long);
				regs.rdx = va_arg(args, unsigned long);
				regs.rcx = va_arg(args, unsigned long);
				break;
			case 5: //RDI, RSI, RDX, RCX, R8
				regs.rdi = va_arg(args, unsigned long);
				regs.rsi = va_arg(args, unsigned long);
				regs.rdx = va_arg(args, unsigned long);
				regs.rcx = va_arg(args, unsigned long);
				regs.r8 = va_arg(args, unsigned long);
				break;
			case 6: //RDI, RSI, RDX, RCX, R8, R9
				regs.rdi = va_arg(args, unsigned long);
				regs.rsi = va_arg(args, unsigned long);
				regs.rdx = va_arg(args, unsigned long);
				regs.rcx = va_arg(args, unsigned long);
				regs.r8 = va_arg(args, unsigned long);
				regs.r9 = va_arg(args, unsigned long);
				break;
			default:
				throw std::runtime_error("Error: Functions with more than 6 parameters are not implemented yet");
		}
		va_end(args);
		regs.rip = (unsigned long)function_address;

		if(inSyscall)	
		{
			regs.rip += 2;
		}

		//128 bytes alignment if needed for the SIMD instructions in dlopen (without library is loaded, but _init is not executed)
		if((regs.rsp & 0xf) == 8) { regs.rsp -= 8; }
		PushToStack(&regs, 0xdeadbeef);
		#ifdef DEBUG
		PrintStack(4);
		#endif
		if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
		{
			perror("ptrace");
			if(!wasPaused) { ResumeExec(); }
			return NULL;
		}
		#ifdef DEBUG
		PrintRegisters();
		#endif
		#ifdef DEBUG_H
		SingleStep(0, true);
		#else
		if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
		{
			perror("ptrace");
			if(!wasPaused) { ResumeExec(); }
			return NULL;
		}
		#endif
		int status = 0;
		waitpid(pid, &status, WUNTRACED); //Wait for the crash on function return
		if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		{
			perror("ptrace");
			if(!wasPaused) { ResumeExec(); }
			return NULL;
		}
		#ifdef DEBUG
		PrintRegisters();
		#endif
		if(regs.rip !=  0xdeadbeef)
		{
			errno = 0x1337;
		}

		if(ptrace(PTRACE_SETREGS, pid, NULL, &save_regs) == -1)
		{
			perror("ptrace");
			if(!wasPaused) { ResumeExec(); }
			return NULL;
		}
		return_value = (void *)regs.rax;
		if(!wasPaused) { ResumeExec(); }
		return return_value;
	}

	bool TracedProcess::PushToStack(struct user_regs_struct* regs, unsigned long data)
	{
		if(!IsPaused()) 
		{
			throw std::runtime_error("Error: The process is not paused");
		}
		if(TracedProcess::WriteMemory((void*)(regs->rsp-sizeof(long)), &data, sizeof(long)) == true)
		{
			regs->rsp -= sizeof(long);
			return true;
		}
		return false;
	}

	bool TracedProcess::WriteMemory(void* write_addr, void* data, int size)
	{
		bool wasPaused = true;
		if(write_addr == NULL || data == NULL || size == 0)
		{
			return false;
		}
		if(!IsPaused()) { PauseExec(); wasPaused = false;}
		for (int i = 0; i < size; i += sizeof(long))
		{
			if (ptrace(PTRACE_POKETEXT, pid, (void*)((unsigned long)write_addr + i), *(unsigned long *)((unsigned long)data + i)) == -1)
			{
				perror("ptrace");
				if(!wasPaused) { ResumeExec(); }
				return false;
			}
		}
		if(!wasPaused) { ResumeExec(); }
		return true;
	}

	int TracedProcess::LoadLibrary(std::string library_name)
	{
		int tries;
		void * buffer_addr;
		void * lib_handle;
		bool check;

		if(Utils::GetLibraryBaseAddress(library_name, pid) != NULL)
		{
			#ifdef DEBUG
			std::cerr << "[-] Library " << library_name << " is already loaded !" << std::endl;
			#endif
			return 0;
		}
		
		tries = 0;
		do
		{
			buffer_addr = CallFunctionAt(malloc_addr, 1, library_name.length()+1);
			tries++;
		} while(errno == 0x1337 && tries < ALLOWED_TRIES);
		if(errno == 0x1337 || buffer_addr == NULL)
		{
			#ifdef DEBUG
			std::cerr << "[-] Failed to get buffer address !" << std::endl;
			#endif
			return -1;
		}
		#ifdef DEBUG
		std::cout << "[+] Buffer : " << buffer_addr << std::endl;
		#endif

		tries = 0;
		do
		{
			check = WriteMemory(buffer_addr, (void*)library_name.c_str(), library_name.length()+1);
			tries++;
		} while(!check && tries < ALLOWED_TRIES);
		if(!check)
		{
			#ifdef DEBUG
			std::cerr << "[-] Failed to write in buffer !" << std::endl;
			#endif
			return -1;
		}
		#ifdef DEBUG
		std::cout << "[+] Write OK" << std::endl;
		#endif

		tries = 0;
		do
		{
			lib_handle = CallFunctionAt(dlopen_addr, 2, buffer_addr, RTLD_LAZY | RTLD_GLOBAL);
			tries++;
		} while(errno == 0x1337 && tries < ALLOWED_TRIES);
		if(errno == 0x1337 || lib_handle == NULL)
		{
			#ifdef DEBUG
			std::cerr << "[-] Failed to get library handle !" << std::endl;
			#endif
			return -1;
		}
		#ifdef DEBUG
		std::cout << "[+] Library Handle : " << lib_handle << std::endl;
		#endif

		tries = 0;
		do
		{
			CallFunctionAt(free_addr, 1, buffer_addr);
			tries++;
		} while(errno == 0x1337 && tries < ALLOWED_TRIES);
		if(errno == 0x1337)
		{
			#ifdef DEBUG
			std::cerr << "[-] Failed to free buffer !" << std::endl;
			#endif
			return -1;
		}
		return 0;		
	}

	void TracedProcess::PrintRegisters()
	{
		struct user_regs_struct regs;
		if(!IsPaused()) 
		{
			throw std::runtime_error("Error: The process is not paused");
		}
		if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		{
			perror("ptrace");
		}
		std::cout << "rax : " << (void*)regs.rax << std::endl;
		std::cout << "rbx : " << (void*)regs.rbx << std::endl;
		std::cout << "rcx : " << (void*)regs.rcx << std::endl;
		std::cout << "rdx : " << (void*)regs.rdx << std::endl;
		std::cout << "rsp : " << (void*)regs.rsp << std::endl;
		std::cout << "rbp : " << (void*)regs.rbp << std::endl;
		std::cout << "rdi : " << (void*)regs.rdi << std::endl;
		std::cout << "rsi : " << (void*)regs.rsi << std::endl;
		std::cout << "r8 : " << (void*)regs.r8 << std::endl;
		std::cout << "r9 : " << (void*)regs.r9 << std::endl;
		std::cout << "r10 : " << (void*)regs.r10 << std::endl;
		std::cout << "r11 : " << (void*)regs.r11 << std::endl;
		std::cout << "r12 : " << (void*)regs.r12 << std::endl;
		std::cout << "rip : " << (void*)regs.rip << std::endl;
		std::cout << std::endl << std::endl;
	}


	void TracedProcess::PrintStack(unsigned long nb)
	{
		struct user_regs_struct regs;
		if(!IsPaused()) 
		{
			throw std::runtime_error("Error: The process is not paused");
		}
		if(ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		{
			perror("ptrace");
		}
		for(unsigned long i = 0; i < nb; i++)
		{
			unsigned long a;
			a = ptrace(PTRACE_PEEKTEXT, pid, regs.rsp + i * sizeof(long), NULL);
			if(errno)
			{
				perror("ptrace");
				return;
			}
			std::cout << "Stack " << i << " => ";
			printf("0x%lx\n", a);
		}
		std::cout << std::endl << std::endl;
	}

	void TracedProcess::SingleStep(unsigned long nb, bool infinite = false)
	{
		if(!IsPaused()) 
		{
			throw std::runtime_error("Error: The process is not paused");
		}
		for(unsigned long i = 0; i < nb || infinite; i++)
		{
			PrintRegisters();
			PrintStack(4);
			int sigNo = 0;
			int waitStat = 0;
	 		const int pRes = ptrace(PTRACE_SINGLESTEP, pid, NULL, sigNo);
			if (pRes < 0)
			{
				perror("Singlestep Error");
				exit(1);
			}

			wait(&waitStat);
			sigNo = WSTOPSIG(waitStat);
			if(sigNo == SIGTRAP)
			{
				sigNo = 0;
			}
			else
			{
				printf("Child got unexpected signal %d\n", sigNo);
				PrintRegisters();
				exit(1);
			   	break;
			}
		}
	}

	TracedProcess::~TracedProcess()
	{
		//PauseExec();
		//ptrace(PTRACE_CONT, pid, NULL, NULL);
		//perror("ptrace");
		int status;
		kill(pid, SIGSTOP);
		waitpid(pid, &status, 0);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		//perror("ptrace");
	}
	
	TracedProcess* Attach(std::string process_name)
	{
		long pid = Utils::GetPIDFromProcessName(process_name);
		TracedProcess* proc = NULL;
		try { proc = new TracedProcess(pid); }
		catch(...) { proc = NULL; }
		return proc;
	}
}
