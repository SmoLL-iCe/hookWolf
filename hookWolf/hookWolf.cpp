#include "shared.h"
#include "shared_class.h"
#include "tools/tools.h"
#include "tools/utils.h"
#include "base_modules/va_module.h"

int main()
{
	auto pid = 0;
	do
	{
		pid = utils::find_process_id( L"BlackDesert64.exe" );
		Sleep( 100 );
	} while ( !pid );
	std::cout << "process found\n";
	auto h_process = OpenProcess( PROCESS_ALL_ACCESS, false, pid );

	if ( !h_process || h_process == INVALID_HANDLE_VALUE )
	{
		std::cout << "invalid handle\n";
		return getchar( );
	}

	std::cout << "loading modules ...\n";
	auto modules = tools::load_modules( h_process );
	std::cout << "modules loaded!\n";
	if ( !modules )
		return 5;

	std::cout << "starting scan ...\n";
	for ( auto mod : modules->all_modules( ) )
	{
		auto runtime_mod = new runtime::va_module( h_process, mod );
		if ( !runtime_mod->valid_pe( ) )
		{
			delete runtime_mod;
			continue;
		}
		std::cout << "import scan ...\n";
		runtime_mod->check_import( modules );
		std::cout << "export scan ...\n";
		runtime_mod->check_export( );
		std::cout << "sections scan ...\n";
		runtime_mod->check_sections( );
	}
	modules->clean( );
	printf( "end checks\n" );
	CloseHandle(h_process);
	return getchar();
}

