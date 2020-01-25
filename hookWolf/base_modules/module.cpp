#include "../shared.h"
#include "../shared_class.h"
#include "../tools/tools.h"

template<typename T>
__forceinline T* base::module_info::rva(const unsigned long offset)
{
	return (T*)ImageRvaToVa(m_nt_headers, m_unmapped_img.data(), offset, nullptr);
}

size_t & base::module_info::virtual_size()
{
	return m_size;
}

std::wstring base::module_info::bin_name( )
{
	std::size_t found = full_name.find_last_of( L"/\\" );
	return full_name.substr( found + 1 );
}
base::module_info::module_info(void* base_mod, size_t size, std::wstring file_name) : m_base(base_mod), m_size( size ), full_name( file_name )
{
	if ( tools::load_file( this ) )
	{ 
		m_dos_header			= reinterpret_cast<IMAGE_DOS_HEADER*>( m_unmapped_img.data() );
		if ( m_dos_header->e_magic				!= IMAGE_DOS_SIGNATURE) return;
		m_nt_headers			= reinterpret_cast<IMAGE_NT_HEADERS*>( m_unmapped_img.data() + m_dos_header->e_lfanew );
		if ( m_nt_headers->Signature			!= IMAGE_NT_SIGNATURE) return;
		if ( m_nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return;
		m_section_header		= reinterpret_cast<IMAGE_SECTION_HEADER*>(r_cast<uintptr_t>(&m_nt_headers->OptionalHeader) + m_nt_headers->FileHeader.SizeOfOptionalHeader);
		valid = true;		
	}
}

base::module_info::~module_info( )
{
	full_name.clear( );
	std::wstring( ).swap( full_name );
	if ( !m_unmapped_img.empty( ) )
	{
		m_unmapped_img.clear( );
		std::vector<uint8_t>( ).swap( m_unmapped_img );
	}
}

bool base::module_info::valid_pe()
{
	return valid;
}

std::wstring base::module_info::path_file()
{
	return full_name;
}

std::vector<uint8_t>& base::module_info::unmapped_img()
{
	return m_unmapped_img;
}

uint8_t* base::module_info::virtual_base()
{
	return r_cast<uint8_t*>( m_base );
}

uint32_t base::module_info::get_unmapped_export_offset( const char * func_name )
{
	ULONG size = 0;
	auto export_dir = static_cast<PIMAGE_EXPORT_DIRECTORY>( ImageDirectoryEntryToData( m_unmapped_img.data(), FALSE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size ) );
	if ( !export_dir )
		return 0;
	auto names		= rva<uint32_t>( export_dir->AddressOfNames );
	auto address	= rva<uint32_t>( export_dir->AddressOfFunctions );
	auto ordinals	= rva<uint16_t>( export_dir->AddressOfNameOrdinals );

	if ( !names || !address || !ordinals )
		return 0;
		
	for (auto i = 0; i < s_cast<int>(export_dir->NumberOfNames); i++)
	{
		auto name = rva<const char>( names[i] );
		if (name && strcmp( name, func_name ) == 0 && ordinals[i] <= export_dir->NumberOfFunctions )
			return address[ordinals[i]];		
	}
	return 0;
}

uint32_t base::module_info::get_unmapped_export_offset( uint16_t ordinal )
{
	ULONG size = 0;
	auto export_dir = static_cast<PIMAGE_EXPORT_DIRECTORY>( ImageDirectoryEntryToData( m_unmapped_img.data(), FALSE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size ) );
	if ( !export_dir )
		return 0;
	auto address	= rva<uint32_t>( export_dir->AddressOfFunctions );
	auto ordinals	= rva<uint16_t>( export_dir->AddressOfNameOrdinals );

	if ( !address || !ordinals )
		return 0;
		
	for (auto i = 0; i < s_cast<int>(export_dir->NumberOfFunctions); i++)
	{
		if ((export_dir->Base + s_cast<uint16_t>(i)) == ordinal) 	
			return address[i];
	}
	return 0;
}

IMAGE_EXPORT_DIRECTORY* base::module_info::get_st_export()
{
	ULONG size = 0;
	return static_cast<PIMAGE_EXPORT_DIRECTORY>(ImageDirectoryEntryToData(m_unmapped_img.data(), FALSE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size));
}

IMAGE_NT_HEADERS* base::module_info::get_st_nt_headers()
{
	return m_nt_headers;
}

IMAGE_SECTION_HEADER* base::module_info::get_st_section_header( )
{
	return m_section_header;
}