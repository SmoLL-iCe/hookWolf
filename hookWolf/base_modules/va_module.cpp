#include "../shared.h"
#include "../shared_class.h"
#include "va_module.h"
#include "../tools/tools.h"

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
	if ( !import_descriptors )
	{
		printf( "no imports!\n" );
		return;
	}

	printf( "-> analise %ls\n", me_mod_info->path_file( ).c_str( ) );
	for ( ; import_descriptors->Name; import_descriptors++ )
	{
		std::string module_name = r_cast<char*>( m_mapped_img.data( ) + import_descriptors->Name );
		if ( module_name.empty( ) )
			continue;
		const auto m_module		= m_modules->get_module( module_name );
		if ( !m_module )
			continue;
		auto thunk = ( import_descriptors->OriginalFirstThunk ) ? import_descriptors->OriginalFirstThunk : import_descriptors->FirstThunk;
		auto image_thunk_data	= r_cast<IMAGE_THUNK_DATA*>( m_mapped_img.data( ) + thunk );
		auto image_func_data	= r_cast<IMAGE_THUNK_DATA*>( m_mapped_img.data( ) + import_descriptors->FirstThunk );

		printf( "-> check module name %s\n", module_name.c_str( ) );
		for ( ; image_thunk_data->u1.AddressOfData; image_thunk_data++, image_func_data++ )
		{
			uint32_t func_offset = 0;
			char* func_name = nullptr;
			if ( ( image_thunk_data->u1.Ordinal & IMAGE_ORDINAL_FLAG ) != 0 )
			{
				const auto impt_ordinal = static_cast<uint16_t>( image_thunk_data->u1.Ordinal & 0xffff );
				func_offset		= m_module->get_unmapped_export_offset( impt_ordinal );
			}
			else
			{
				const auto img_impt_name = r_cast<IMAGE_IMPORT_BY_NAME*>( m_mapped_img.data( ) + *reinterpret_cast<uint32_t*>( image_thunk_data ) );
				func_name		= static_cast<char*>( img_impt_name->Name );
				func_offset		= m_module->get_unmapped_export_offset( func_name );
			}
			if ( func_offset && func_name )
			{
				auto real_address = ( m_module->virtual_base( ) + func_offset );
				printf( "---> func_name: %25s -> now ptr 0x%p, real ptr 0x%p\n", func_name, r_cast<void*>( image_func_data->u1.Function ), real_address );
			}
			else if ( func_offset )
			{
				auto real_address = ( m_module->virtual_base( ) + func_offset );
				printf( "---> func_name: by_ordinal -> now ptr 0x%p, real ptr 0x%p\n", r_cast<void*>( image_func_data->u1.Function ), real_address );
			}
		}
	}
}

void runtime::va_module::check_export( )
{
	auto rt_export_dir	= r_cast<PIMAGE_EXPORT_DIRECTORY>( m_mapped_img.data( ) + m_nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
	auto export_dir		= me_mod_info->get_st_export( );
	if ( !rt_export_dir || !export_dir )
	{
		printf( "no exports!\n" );
		return;
	}

	if ( rt_export_dir->TimeDateStamp		!= export_dir->TimeDateStamp		||
		 rt_export_dir->NumberOfNames		!= export_dir->NumberOfNames		||
		 rt_export_dir->NumberOfFunctions	!= export_dir->NumberOfFunctions	||
		 rt_export_dir->AddressOfNames		!= export_dir->AddressOfNames		||
		 rt_export_dir->AddressOfFunctions	!= export_dir->AddressOfFunctions	)
	{
		printf( "incompatible exports!\n" );
		system( "pause" );
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
		for ( auto i = 0; i < s_cast<int>( rt_export_dir->NumberOfFunctions ); i++ )
		{
			auto const valid_name	= ( i < s_cast<int>( rt_export_dir->NumberOfNames ) );
			const char* rt_name		= ( valid_name ) ? r_cast<const char*>( m_mapped_img.data( ) + rt_names[ i ] ) : nullptr;
			auto const ordinal		= ( rt_ordinals[ i ] );
			if ( valid_name )
				printf( "name %s, ", rt_name );
			else
				printf( "ordinal %hu, ", ordinal );
			if ( rt_address[ ordinal ] != rt_address[ ordinal ] )
			{
				printf( "EAT diferente\n" );
				system( "pause" );
			}
			else
			{
				printf( "EAT igual\n" );
			}
		}
	}
}

void runtime::va_module::check_sections( )
{
	auto static_nt_headers = me_mod_info->get_st_nt_headers( );
	if ( !static_nt_headers || !m_nt_headers )
		return;
	if ( static_nt_headers->FileHeader.NumberOfSections != m_nt_headers->FileHeader.NumberOfSections )
		return;
	for ( size_t i = 0; i < m_nt_headers->FileHeader.NumberOfSections; ++i )
	{
		const auto& section		= m_section_header[ i ];
		const auto va_section	= m_mapped_img.data( ) + section.VirtualAddress;		
		const auto st_section	= me_mod_info->unmapped_img( ).data( ) + section.PointerToRawData;		
		printf( "Section [%s] VA[0x%p] ST[0x%p] Size[0x%04X]\n", &section.Name[ 0 ], va_section, st_section, section.SizeOfRawData );
	}
}

runtime::va_module::~va_module( )
{
	if ( m_mapped_img.empty( ) )
		return;
	m_mapped_img.clear( );
	std::vector<uint8_t>( ).swap( m_mapped_img );
}