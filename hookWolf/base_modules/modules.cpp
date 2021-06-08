#include "../shared.h"
#include "base_modules.h"
#include "../tools/utils.h"

base::modules::modules( std::vector<module_info*> v_m_modules ) : m_modules( std::move( v_m_modules ) )
{
	for ( auto& mod : m_modules )
	{

		if ( !mod->unmapped_img( ).empty( ) )
			++m_size;
	}

	m_valid = ( m_size );
}

std::vector<base::module_info*> base::modules::all_modules( )
{
	return m_modules;
}

base::module_info* base::modules::get_module( std::string mod_name )
{

	std::wstring w_mod_name( mod_name.begin( ), mod_name.end( ) );

	for ( auto& mod : m_modules )
	{
		auto str_source = utils::get_file_name( mod->path_file( ) );

		if ( utils::str_lower( str_source ).find( utils::str_lower( w_mod_name ) ) != -1 )
			return mod;
	}
	return nullptr;
}

void base::modules::clean( )
{
	for ( auto& mod : m_modules )
	{
		delete mod;
	}

	m_modules.clear( );

	std::vector<base::module_info*>( ).swap( m_modules );
}

base::modules::~modules( )
{
	this->clean( );
}