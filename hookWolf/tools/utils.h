#pragma once
namespace utils
{
	std::wstring get_file_name( const std::wstring& str );
	std::wstring str_lower( std::wstring& str );
	std::string  str_lower( std::string& str );
	std::wstring str_replace( std::wstring str, const std::wstring& from, const std::wstring& to );
	std::wstring remove_device( std::wstring device_path );
	bool open_bin_file( const std::wstring& file, std::vector<uint8_t>& data );
	uint32_t find_process_id( std::wstring processName );
}