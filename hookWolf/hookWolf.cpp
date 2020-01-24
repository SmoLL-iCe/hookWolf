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
		pid = utils::find_process_id( L"test_s64.exe" );
		Sleep( 100 );
	} while ( !pid );
	std::cout << "process found\n";
	auto h_process = OpenProcess( PROCESS_ALL_ACCESS, false, pid );
	std::cout << "handle: 0x" << h_process << "\n";

	auto modules = tools::load_modules( h_process );

	if ( !modules )
		return 5;
	for ( auto mod : modules->all_modules( ) )
	{
		//printf("mod %p\n", mod->image().data());
		auto rt_mod = new runtime::va_module( h_process, mod );
		if ( !rt_mod->valid_pe( ) )
		{
			delete rt_mod;
			continue;
		}
		//rt_mod->check_import( modules );
		rt_mod->check_export( );
	}
	modules->clean( );

	printf( "end checks\n" );
	CloseHandle(h_process);
	return getchar();
}

