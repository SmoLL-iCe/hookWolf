#include "shared.h"
#include "base_modules/base_modules.h"
#include "tools/tools.h"
#include "tools/utils.h"
#include "base_modules/rt_module.h"
#include <string>

int main()
{
	std::cout << "hookWolf v1.0 \n\n";

	std::wstring proc{ };

	std::cout << "process name: ";

	std::getline( std::wcin, proc );

	DWORD pid = 0;
	do
	{
		pid = utils::find_process_id( proc );

		Sleep( 100 );

	} while ( !pid );

	std::cout << "process found\n";

	system("pause" );

	auto* const h_process = OpenProcess( PROCESS_ALL_ACCESS, false, pid );

	if ( !h_process || h_process == INVALID_HANDLE_VALUE )
	{
		std::cout << "invalid handle\n";
		return getchar( );
	}

	// if any process wants to close this handle
	SetHandleInformation( h_process, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE );

	std::cout << "loading modules ...\n";
	auto* modules = tools::load_modules( h_process );

	std::cout << "modules loaded!\n";
	if ( !modules )
		return 5;

	std::cout << "starting scan ...\n";
	for (auto* mod : modules->all_modules( ) )
	{

		auto* runtime_mod = new runtime::rt_module( h_process, mod );

		if ( !runtime_mod->valid_pe( ) )
		{
			delete runtime_mod;
			continue;
		}

		std::wcout << "scan module " << mod->bin_name( ).c_str( ) << "\n";

		std::cout << "import scan ...\n";

		runtime_mod->check_import( modules );

		std::cout << "export scan ...\n";

		runtime_mod->check_export( );

		std::cout << "sections scan ...\n";

		runtime_mod->check_sections( );
	}

	modules->clean( );

	printf( "end checks\n" );

	// return close access
	SetHandleInformation( h_process, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_INHERIT );

	CloseHandle( h_process );

	return getchar();
}

