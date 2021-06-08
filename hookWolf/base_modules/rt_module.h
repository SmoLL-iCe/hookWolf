#pragma once
namespace runtime
{
	class rt_module
	{
	public:
		explicit rt_module( HANDLE h_process, base::module_info* mod );

		~rt_module( );

		std::vector<uint8_t> mapped_img( ) const;

		void check_import( base::modules* m_modules );

		void check_export( );

		void check_sections( );

		bool valid_pe( ) const;

	private:
		struct expts_funcs_aligned
		{
			uint32_t start	= 0;

			uint32_t end	= 0;

			uint32_t index	= 0;
		};
		std::vector<uint8_t>	m_mapped_img{};

		bool valid									= false;

		IMAGE_DOS_HEADER*		m_dos_header		= nullptr;

		IMAGE_NT_HEADERS*		m_nt_headers		= nullptr;

		IMAGE_SECTION_HEADER*	m_section_header	= nullptr;

		base::module_info*		me_mod_info			= nullptr;

		template<typename T>
		__forceinline T* va(const unsigned long offset);


		/// <summary>
		/// compare the two exports to see if they are the same.
		/// </summary>
		/// <param name="rt_export_dir">runtime export</param>
		/// <param name="export_dir">static export</param>
		/// <returns>return true if equal</returns>
		static bool cmp_exports_is_valid( IMAGE_EXPORT_DIRECTORY* rt_export_dir, IMAGE_EXPORT_DIRECTORY* export_dir );

		std::vector<expts_funcs_aligned> align_export( IMAGE_EXPORT_DIRECTORY* export_dir );
	};

}

