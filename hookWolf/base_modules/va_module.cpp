#include "../shared.h"
#include "../shared_class.h"
#include "va_module.h"
#include "../tools/tools.h"
#include "../tools/utils.h"

template<typename T>
__forceinline T* runtime::va_module::rva( const unsigned long offset )
{
	return (T*)ImageRvaToVa( me_mod_info->get_st_nt_headers( ), me_mod_info->unmapped_img( ).data( ), offset, nullptr );
}

runtime::va_module::va_module( HANDLE h_process, base::module_info* mod ) : me_mod_info( mod )
{
	m_mapped_img.reserve(	me_mod_info->virtual_size( ) );
	m_mapped_img.resize(	me_mod_info->virtual_size( ) );
	if ( m_mapped_img.empty( ) || !win::rpm( h_process, me_mod_info->virtual_base( ), m_mapped_img.data( ), me_mod_info->virtual_size( ) ) )
		return;
	m_dos_header		= reinterpret_cast<IMAGE_DOS_HEADER*>( m_mapped_img.data( ) );
	if ( m_dos_header->e_magic				!= IMAGE_DOS_SIGNATURE ) return;
	m_nt_headers		= reinterpret_cast<IMAGE_NT_HEADERS*>( m_mapped_img.data( ) + m_dos_header->e_lfanew );
	if ( m_nt_headers->Signature			!= IMAGE_NT_SIGNATURE ) return;
	if ( m_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC ) return;
	m_section_header	= reinterpret_cast<IMAGE_SECTION_HEADER*>( r_cast<uintptr_t>( &m_nt_headers->OptionalHeader ) + m_nt_headers->FileHeader.SizeOfOptionalHeader );
	valid = true;
}

std::vector<uint8_t> runtime::va_module::mapped_img( )
{
	return m_mapped_img;
}

bool runtime::va_module::valid_pe( )
{
	return valid;
}

void runtime::va_module::check_import( base::modules* m_modules )
{
	auto import_descriptors		= r_cast<PIMAGE_IMPORT_DESCRIPTOR>( m_mapped_img.data( ) + m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );
	if ( !import_descriptors || !tools::is_valid_read( import_descriptors ) )
	{
		printf( "invalid import in module: %ls\n", me_mod_info->bin_name( ).c_str( ) );
		return;
	}
	for ( ; import_descriptors->Name; import_descriptors++ )
	{
		auto mod_name = r_cast<char*>( m_mapped_img.data( ) + import_descriptors->Name );
		if ( !mod_name || !tools::is_valid_read( mod_name ) )
			continue;
		
		std::string module_name( mod_name );
		const auto m_module		= m_modules->get_module( module_name );
		if ( !m_module )
			continue;
		auto thunk = ( import_descriptors->OriginalFirstThunk ) ? import_descriptors->OriginalFirstThunk : import_descriptors->FirstThunk;
		auto image_thunk_data	= r_cast<IMAGE_THUNK_DATA*>( m_mapped_img.data( ) + thunk );
		auto image_func_data	= r_cast<IMAGE_THUNK_DATA*>( m_mapped_img.data( ) + import_descriptors->FirstThunk );

		for ( ; tools::is_valid_read( image_thunk_data) && tools::is_valid_read( image_func_data) && image_thunk_data->u1.AddressOfData; image_thunk_data++, image_func_data++ )
		{
			uint32_t func_offset = 0;
			char* func_name = nullptr;
			uint16_t ordinal = 0;
			if ( ( image_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG ) != 0 )
			{
				ordinal			= static_cast<uint16_t>( image_thunk_data->u1.Ordinal & 0xffff );
				func_offset		= m_module->get_unmapped_export_offset( ordinal );
			}
			else
			{
				const auto img_impt_name	= r_cast<IMAGE_IMPORT_BY_NAME*>( m_mapped_img.data( ) + *reinterpret_cast<uint32_t*>( image_thunk_data ) );
				func_name					= static_cast<char*>( img_impt_name->Name );
				func_offset					= m_module->get_unmapped_export_offset( func_name );
			}
			if ( func_offset )
			{
				auto real_address = r_cast<uintptr_t>( m_module->virtual_base( ) + func_offset );
				if ( image_func_data->u1.Function == real_address )
					continue;
				printf( "Hook IAT in module: %15ls, ", me_mod_info->bin_name( ).c_str( ));
				if ( func_name )
					printf( "func_name: %25s, ", func_name );
				else
					printf( "ordinal %hu, ", ordinal );
				printf( "patch: 0x%I64X, original: 0x%I64X\n", image_func_data->u1.Function, real_address );
			}

		}
	}
}

bool runtime::va_module::cmp_exports_is_valid( IMAGE_EXPORT_DIRECTORY * rt_export_dir, IMAGE_EXPORT_DIRECTORY* export_dir )
{
	if ( !rt_export_dir || !export_dir )
		return false;

	return !( 
	rt_export_dir->TimeDateStamp		!= export_dir->TimeDateStamp		||
	rt_export_dir->NumberOfNames		!= export_dir->NumberOfNames		||
	rt_export_dir->NumberOfFunctions	!= export_dir->NumberOfFunctions	||
	rt_export_dir->AddressOfNames		!= export_dir->AddressOfNames		||
	rt_export_dir->AddressOfFunctions	!= export_dir->AddressOfFunctions	);
}

void runtime::va_module::check_export( )
{
	auto rt_export_dir	= r_cast<PIMAGE_EXPORT_DIRECTORY>( m_mapped_img.data( ) + m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
	auto export_dir		= me_mod_info->get_st_export( );
	if ( !cmp_exports_is_valid( rt_export_dir , export_dir ) )
	{ 
		printf( "invalid export\n" );
		return;
	}
	auto rt_names		= r_cast<uint32_t*>( m_mapped_img.data( ) + rt_export_dir->AddressOfNames			);
	auto rt_address		= r_cast<uint32_t*>( m_mapped_img.data( ) + rt_export_dir->AddressOfFunctions		);
	auto rt_ordinals	= r_cast<uint16_t*>( m_mapped_img.data( ) + rt_export_dir->AddressOfNameOrdinals	);

	auto st_names		= rva<uint32_t>( export_dir->AddressOfNames			);
	auto st_address		= rva<uint32_t>( export_dir->AddressOfFunctions		);
	auto st_ordinals	= rva<uint16_t>( export_dir->AddressOfNameOrdinals	);
	if ( rt_names && rt_address && rt_ordinals )
	{
		for ( auto i = 0; i < s_cast<int>( rt_export_dir->NumberOfNames ); i++ )
		{
			const char* rt_name		= r_cast<const char*>( m_mapped_img.data( ) + rt_names[ i ] );
			auto const rt_ordinal	= ( rt_ordinals[ i ] );
			auto const st_ordinal	= ( st_ordinals[ i ] );


			if ( rt_address[ rt_ordinal ] != st_address[ st_ordinal ] )
			{
				printf( "Hook EAT in module: %15ls, ", me_mod_info->bin_name( ).c_str( ) );
				if ( rt_name )
					printf( "name %25s, ", rt_name );
				else
					printf( "ordinal %hu, ", rt_ordinal );
				printf( "patch 0x%X, original 0x%X\n" , rt_address[ rt_ordinal ] , st_address[ st_ordinal ] );
			}
		}
	}
}



std::vector<runtime::va_module::expts_funcs_aligned> runtime::va_module::align_export( IMAGE_EXPORT_DIRECTORY* export_dir )
{
	auto st_names		= rva<uint32_t>( export_dir->AddressOfNames			);
	auto st_address		= rva<uint32_t>( export_dir->AddressOfFunctions		);
	auto st_ordinals	= rva<uint16_t>( export_dir->AddressOfNameOrdinals	);

	std::vector<expts_funcs_aligned> m_export_passed {};
	if ( st_names && st_address && st_ordinals )
	{
			
		for ( auto x = 0; x < s_cast<int>( export_dir->NumberOfNames ); x++ )
		{
			auto const	start_address	= ( st_address[ st_ordinals[ x ] ] );
			uint32_t	end_address		= ( 0 );
			for ( auto i = 0; i < s_cast<int>( export_dir->NumberOfFunctions ); i++ )
			{
				auto const check_address = ( st_address[ st_ordinals[ i ] ] );
				if ( start_address >= check_address )
					continue;
				if ( !end_address || check_address < end_address )
					end_address = check_address;
			}

			m_export_passed.push_back( { start_address, end_address, s_cast<uint32_t>(x) } );
		}
		for ( auto & export_info : m_export_passed )
		{
			if ( !export_info.end )
				export_info.end = 500;
			auto s_address	= rva<uint8_t>( export_info.start );
			auto to_bytes	= ( export_info.end - export_info.start );
			auto adjusted	= false;
			for ( uint32_t i = 0; i < to_bytes; i++ )
				if ( !tools::is_valid_read( &s_address[ i+4 ] ) || *reinterpret_cast<uint32_t*>( &s_address[ i ] ) == 0xCCCCCCCC  )
				{
					export_info.end = export_info.start + (i-1);
					adjusted = true;
					break;
				}		
			if ( !adjusted )
				--export_info.end;
		}
	}
	return m_export_passed;
}

void runtime::va_module::check_sections( )
{
	uint32_t display_patch_limit = 16;
	auto static_nt_headers = me_mod_info->get_st_nt_headers( );
	if ( !static_nt_headers || !m_nt_headers )
		return;
	if ( static_nt_headers->FileHeader.NumberOfSections != m_nt_headers->FileHeader.NumberOfSections )
		return;
	
	for ( size_t i = 0; i < m_nt_headers->FileHeader.NumberOfSections; ++i )
	{
		const auto& va_section			= m_section_header[ i ];
		const auto& st_section			= me_mod_info->get_st_section_header( )[ i ];
		auto section_name				= std::string( r_cast<const char*>( &va_section.Name[ 0 ] ) );
		auto section_lower_name			= utils::str_lower( section_name );
		
		if ( !strstr( section_lower_name.c_str( ), "text" ) && !strstr( section_lower_name.c_str( ), "code" ) )
			continue;

		if ( !va_section.SizeOfRawData || !st_section.SizeOfRawData || ( va_section.SizeOfRawData != st_section.SizeOfRawData ) )
			continue;

		const auto va_section_ptr	= m_mapped_img.data( ) + va_section.VirtualAddress;		
		const auto st_section_ptr	= me_mod_info->unmapped_img( ).data( ) + va_section.PointerToRawData;
		struct patchs
		{
			uint32_t index_start	= 0;
			uint32_t index_end		= 0;
			uint32_t off			= 0;
			const char* name = nullptr;
		};
		std::vector<patchs> m_patchs {};
		uint32_t init = 0;
		for ( uint32_t i = 0, changed = 0, equal = 0; i < st_section.SizeOfRawData; i++ )
		{
			if ( va_section_ptr[ i ] != st_section_ptr[ i ] )
			{
				if ( !changed )
					init = i;
				++changed;
				equal = 0;
			}
			else 
			{
				if ( changed && equal >= 5)
				{
					m_patchs.push_back( { init, i - equal } );
					init = changed = 0;
				}
				++equal;
			}
		}
		if ( init )
			m_patchs.push_back( { init, st_section.SizeOfRawData } );
		if ( m_patchs.empty( ) )
			return;

		auto rt_export_dir	= r_cast<PIMAGE_EXPORT_DIRECTORY>( m_mapped_img.data( ) + m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
		auto export_dir		= me_mod_info->get_st_export( );
		std::vector<expts_funcs_aligned> expts_aligned {};
		
		if ( cmp_exports_is_valid( rt_export_dir, export_dir ) )
			expts_aligned = align_export( export_dir );
		if ( !expts_aligned.empty( ) )
		{
			auto st_names = rva<uint32_t>( export_dir->AddressOfNames );
			for ( auto& patch : m_patchs )
			{
				for ( auto expt_aligned : expts_aligned )
				{
					auto start = ( va_section.VirtualAddress + patch.index_start );
					if ( !( expt_aligned.start <= start && start <= expt_aligned.end ) )
						continue;
					patch.off	= ( start - expt_aligned.start );
					patch.name	= rva<const char>( st_names[ expt_aligned.index ] );
					break;
				}
			}
			expts_aligned.clear( );
			std::vector<expts_funcs_aligned>( ).swap( expts_aligned );
		}
		
		for ( auto patch : m_patchs )
		{
			auto start			= ( va_section.VirtualAddress + patch.index_start );
			auto end			= ( va_section.VirtualAddress + patch.index_end );
			auto total_bytes	= ( patch.index_end - patch.index_start );
			printf( "Hook inline in module: %ls", me_mod_info->bin_name( ).c_str( ) );
			auto m_end = ( total_bytes > display_patch_limit ) ? (patch.index_start  + display_patch_limit ) : patch.index_end;
			if ( patch.name )
			{
				std::string str_name( patch.name );
				printf( "!%s", str_name.c_str() );
				if ( patch.off )
					printf( "+0x%X", patch.off );

				printf( ", patch: " );
				for ( auto x = patch.index_start; x < m_end; x++ )
					printf( "%02X ", va_section_ptr[ x ] );
				if ( m_end != patch.index_end )
					printf( "+%d ", ( patch.index_end - ( patch.index_start + display_patch_limit ) ) );

				printf( ", original: " );
				for (auto x = patch.index_start; x < m_end; x++ )
					printf( "%02X ", st_section_ptr[ x ] );
				if ( m_end != patch.index_end )
					printf( "+%d ", ( patch.index_end - ( patch.index_start + display_patch_limit ) ) );
				printf( "\n" );
			}
			else
			{
				printf( "+0x%X, patch: ", start );
				for ( auto x = patch.index_start; x < m_end; x++ )
					printf( "%02X ", va_section_ptr[ x ] );
				if ( m_end != patch.index_end )
					printf( "+%d ", ( patch.index_end - ( patch.index_start + display_patch_limit ) ) );

				printf( ", original: " );
				for ( auto x = patch.index_start; x < m_end; x++ )
					printf( "%02X ", st_section_ptr[ x ] );
				if ( m_end != patch.index_end )
					printf( "+%d ", ( patch.index_end - ( patch.index_start + display_patch_limit ) ) );
				printf( "\n" );
			}

		}

	}

}
/*
tsfGetAsyncKeyState = start: 00007FF96EEFAC40, end: 00007FF96EEFACD0
tsfGetKeyState = start: 00007FF96EED2D00, end: 00007FF96EED64F0
*/

runtime::va_module::~va_module( )
{
	if ( m_mapped_img.empty( ) )
		return;
	m_mapped_img.clear( );
	std::vector<uint8_t>( ).swap( m_mapped_img );
}