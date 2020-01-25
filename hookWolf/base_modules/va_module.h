#pragma once
namespace runtime
{
	class va_module
	{
	public:
		explicit va_module( HANDLE h_process, base::module_info* mod );
		~va_module( );
		std::vector<uint8_t> mapped_img( );
		void check_import( base::modules* m_modules );
		void check_export( );
		void check_sections( );
		bool valid_pe( );
	private:
		struct expts_funcs_aligned
		{
			uint32_t start = 0;
			uint32_t end = 0;
			uint32_t index = 0;
		};
		std::vector<uint8_t>	m_mapped_img{};
		bool valid									= false;
		IMAGE_DOS_HEADER*		m_dos_header		= nullptr;
		IMAGE_NT_HEADERS*		m_nt_headers		= nullptr;
		IMAGE_SECTION_HEADER*	m_section_header	= nullptr;
		base::module_info*		me_mod_info			= nullptr;
		template<typename T>
		__forceinline T* rva(const unsigned long offset);
		bool cmp_exports_is_valid( IMAGE_EXPORT_DIRECTORY* rt_export_dir, IMAGE_EXPORT_DIRECTORY* export_dir );
		std::vector<runtime::va_module::expts_funcs_aligned> align_export( IMAGE_EXPORT_DIRECTORY* export_dir );
	};

}

