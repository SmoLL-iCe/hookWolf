#include "../shared.h"
#include "../shared_class.h"
#include "tools.h"
#include "ntos.h"
#include "utils.h"

NTSTATUS last_status = 0;
size_t win::virtual_query(HANDLE h_process, void* p_address, uint32_t e_class, void* p_buffer, const size_t dw_length)
{
	size_t  return_len = 0;
	last_status = NtQueryVirtualMemory( h_process, p_address, s_cast<MEMORY_INFORMATION_CLASS>(e_class), p_buffer, dw_length, &return_len);
	return return_len;
}

bool win::rpm(HANDLE h_process, void* p_address, void* p_buffer, const size_t dw_length)
{
	size_t  return_len = 0;
	last_status = NtReadVirtualMemory(h_process, p_address, p_buffer, dw_length, &return_len);
	return ( NT_SUCCESS( last_status ) && return_len );
}

DWORD readable = ( PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY );
DWORD writable = ( PAGE_EXECUTE_READWRITE | PAGE_READWRITE );
DWORD forbidden = ( PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS );

bool tools::is_valid_read( void* p )
{
	MEMORY_BASIC_INFORMATION mbi = {};
	mbi.Protect = 0;
	return ( win::virtual_query( GetCurrentProcess(), p, 0, &mbi, sizeof mbi ) && ( mbi.Protect & forbidden ) == 0 && ( mbi.Protect & readable ) != 0 );
}

bool tools::load_file( base::module_info * mod_info )
{
	//HANDLE				h_file			= nullptr;
	//OBJECT_ATTRIBUTES	obj_atts		= { 0 };
	//IO_STATUS_BLOCK		io_stts_block	= { 0 };
	//LARGE_INTEGER		large_int		= { 0 };
	//UNICODE_STRING		uni_str			= { 0 };
	//RtlInitUnicodeString(&uni_str, ( L"\\??\\" + mod_info->path_file() ).c_str());
	//InitializeObjectAttributes( &obj_atts, &uni_str, OBJ_CASE_INSENSITIVE, nullptr, nullptr );
	//if ( !NT_SUCCESS( last_status = NtCreateFile( &h_file, FILE_READ_DATA, &obj_atts, &io_stts_block, &large_int, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, nullptr, 0 )))
	//{

	//	printf("last_status %X, #%ls#\n", last_status, mod_info->path_file().c_str());
	//	return false;
	//}
	//auto f_size = static_cast<SIZE_T>( GetFileSize( h_file, nullptr ) );
	//HANDLE h_section = nullptr;
	//if ( !NT_SUCCESS( last_status = NtCreateSection(&h_section, SECTION_MAP_READ | SECTION_MAP_WRITE | DELETE, nullptr, &large_int, PAGE_READONLY, SEC_COMMIT, h_file)) )
	//{ 
	//	NtClose( h_file );
	//	return false;
	//}
	// void* img_base = nullptr;
	//SIZE_T view_size = 0;
	//if ( !NT_SUCCESS( last_status = NtMapViewOfSection(h_section, GetCurrentProcess(), &img_base, 0, 0, nullptr, &view_size, ViewUnmap, 0, PAGE_READONLY) ) )
	//{
	//	NtClose( h_section );
	//	NtClose( h_file );
	//	return false;
	//}
	//view_size = 0;
	//mod_info->unmapped_img().reserve( f_size );
	//mod_info->unmapped_img().resize( f_size );
	//memcpy( mod_info->unmapped_img().data(), img_base, f_size );
	//NtUnmapViewOfSection( NtCurrentProcess(), img_base );
	//NtFreeVirtualMemory( NtCurrentProcess(), &img_base, &view_size, MEM_RELEASE );
	//NtClose( h_section );
	//NtClose( h_file );
	//return true;
	return utils::open_bin_file( mod_info->path_file( ), mod_info->unmapped_img( ) );
}

base::modules* tools::load_modules(HANDLE h_process)
{
	struct
	{
		OBJECT_NAME_INFORMATION obj_name_info;
		wchar_t file_name[MAX_PATH];
	} file_name;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	std::vector<base::module_info*> m_modules{};
	std::wstring last_file(L"");
	for (uint8_t* address = nullptr;
		win::virtual_query(h_process, address, MemoryBasicInformation, &mbi, sizeof mbi );
		address = reinterpret_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize)
	{
		if ( mbi.Type != MEM_IMAGE )
			continue;

		if ( !win::virtual_query( h_process, mbi.BaseAddress, MemoryMappedFilenameInformation, &file_name, sizeof file_name ) )
			continue;

		if ( !file_name.obj_name_info.Name.Buffer )
			continue;

		if ( !wcscmp( file_name.obj_name_info.Name.Buffer, last_file.c_str() ) )
		{			
			m_modules.back()->virtual_size() += mbi.RegionSize;
			continue;
		}
		last_file = file_name.obj_name_info.Name.Buffer;
		m_modules.push_back( new base::module_info( mbi.BaseAddress , mbi.RegionSize, utils::remove_device( file_name.obj_name_info.Name.Buffer ) ) );
	}
	if ( !m_modules.empty() )
		return new base::modules( m_modules );
		
	return nullptr;
}