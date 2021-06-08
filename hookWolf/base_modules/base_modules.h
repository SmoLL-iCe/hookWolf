#pragma once
namespace base
{
	class module_info
	{
	public:

		module_info( void* base_mod, size_t size, std::wstring file_name );

		~module_info( );

		/// <summary>
		/// get the export of the loaded PE that came from local storage. 
		/// </summary>
		/// <param name="func_name">function name</param>
		/// <returns>only offset of export</returns>
		uint32_t get_unmapped_export_offset( const char * func_name );

		/// <summary>
		/// get the export of the loaded PE that came from local storage, by ordinal. 
		/// </summary>
		/// <param name="ordinal">ordinal value</param>
		/// <returns>only offset of export</returns>
		uint32_t get_unmapped_export_offset( uint16_t ordinal );

		/// <summary>
		/// get static module export
		/// </summary>
		/// <returns>image of export dir ptr</returns>
		IMAGE_EXPORT_DIRECTORY* get_st_export();

		/// <summary>
		/// get static module size
		/// </summary>
		/// <returns>size of module</returns>
		size_t & virtual_size();

		/// <summary>
		/// full path of the file
		/// </summary>
		/// <returns>unicode string with full path of file</returns>
		std::wstring path_file() const;

		/// <summary>
		/// get only module name
		/// </summary>
		/// <returns>unicode string with the module name</returns>
		std::wstring bin_name( ) const;

		/// <summary>
		/// if PE was analyzed 
		/// </summary>
		/// <returns>is valid pe</returns>
		bool valid_pe() const;

		/// <summary>
		/// return module buffer unmapped
		/// </summary>
		/// <returns>buffer of file in vector byte</returns>
		std::vector<uint8_t>& unmapped_img();

		/// <summary>
		/// current module rva base
		/// </summary>
		/// <returns>base ptr</returns>
		uint8_t* virtual_base() const;

		/// <summary>
		/// get static module nt headers
		/// </summary>
		/// <returns>image nt headers ptr</returns>
		IMAGE_NT_HEADERS* get_st_nt_headers() const;

		/// <summary>
		/// get static module sections header
		/// </summary>
		/// <returns>image section header ptr</returns>
		IMAGE_SECTION_HEADER* get_st_section_header( ) const;

	private:

		bool					m_valid				= false;

		void*					m_base				= nullptr;

		size_t					m_size				= 0;

		std::wstring			m_full_name			= { };

		std::vector<uint8_t>	m_unmapped_img		= { };

		IMAGE_DOS_HEADER*		m_dos_header		= nullptr;

		IMAGE_NT_HEADERS*		m_nt_headers		= nullptr;

		IMAGE_SECTION_HEADER*	m_section_header	= nullptr;

		template<typename T>
		__forceinline T* va(const unsigned long offset);

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
		std::vector<base::module_info*> m_modules	= {};
		size_t							m_size		= 0;
		bool							m_valid		= false;
	};
}