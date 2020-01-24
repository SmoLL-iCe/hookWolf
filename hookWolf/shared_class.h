#pragma once
namespace base
{
	class module_info
	{
	public:
		module_info( void* base_mod, size_t size, std::wstring file_name );
		~module_info( );
		uint32_t get_unmapped_export_offset( const char * func_name );
		uint32_t get_unmapped_export_offset( uint16_t ordinal );
		IMAGE_EXPORT_DIRECTORY* get_st_export();
		size_t & virtual_size();
		std::wstring path_file();
		bool valid_pe();
		std::vector<uint8_t>& unmapped_img();
		uint8_t* virtual_base();
		IMAGE_NT_HEADERS* get_st_nt_headers();
	private:
		bool valid				= false;
		void* m_base			= nullptr;
		size_t m_size			= 0;
		std::wstring full_name{};
		std::vector<uint8_t>	m_unmapped_img{};
		IMAGE_DOS_HEADER*		m_dos_header		= nullptr;
		IMAGE_NT_HEADERS*		m_nt_headers		= nullptr;
		IMAGE_SECTION_HEADER*	m_section_header	= nullptr;
		template<typename T>
		__forceinline T* rva(const unsigned long offset);
	};
	class modules
	{
	public:
		modules( std::vector<module_info*> v_m_modules );
		std::vector<module_info*> all_modules( );
		module_info* get_module( std::string mod_name );
		void clean( );
		~modules( );
	private:
		std::vector<base::module_info*> m_modules{};
		size_t m_size	= 0;
		bool valid		= false;
	};
}