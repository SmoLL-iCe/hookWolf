#pragma once
namespace win 
{
	size_t virtual_query( HANDLE h_process, void* p_address, uint32_t e_class, void* p_buffer, const size_t dw_length );
	bool rpm( HANDLE h_process, void* p_address, void* p_buffer, const size_t dw_length );
}
namespace tools
{
	base::modules* load_modules( HANDLE h_process );
	bool load_file( base::module_info* mod_info );
	bool is_valid_read( void* p );

}
