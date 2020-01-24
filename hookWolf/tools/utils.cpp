#include "../shared.h"
#include "utils.h"
#include <algorithm>
#include <iterator>
#include <fstream>
#include <tlhelp32.h>


uint32_t utils::find_process_id( std::wstring processName )
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof processInfo ;

	HANDLE processSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
	if ( processSnapshot == INVALID_HANDLE_VALUE )
		return 0;

	Process32First( processSnapshot, &processInfo );
	if ( !processName.compare( processInfo.szExeFile ) )
	{
		CloseHandle( processSnapshot );
		return processInfo.th32ProcessID;
	}

	while ( Process32Next( processSnapshot, &processInfo ) )
	{
		if ( !processName.compare( processInfo.szExeFile ) )
		{
			CloseHandle( processSnapshot );
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle( processSnapshot );
	return 0;
}

std::wstring utils::get_file_name( const std::wstring& str )
{
	std::size_t found = str.find_last_of( L"/\\" );
	return str.substr( found + 1 );
}

std::wstring utils::str_lower( std::wstring& str )
{
	std::wstring str_dest {};
	str_dest.resize( str.size( ) );
	std::transform( str.begin( ), str.end( ), str_dest.begin( ), ::tolower );
	return str_dest;
}

struct volume_info
{
	std::wstring letter {};
	std::wstring vol_device {};
};
std::vector<volume_info> vol_info {};

void update_volumes_info( )
{

	wchar_t device_name[ MAX_PATH ] = L"";
	wchar_t volume_name[ MAX_PATH ] = L"";
	auto h_find = FindFirstVolumeW( volume_name, ARRAYSIZE( volume_name ) );
	if ( h_find == INVALID_HANDLE_VALUE )
		return;
	do
	{
		auto index = wcslen( volume_name ) - 1;
		if ( volume_name[ 0 ] != L'\\' || volume_name[ 1 ] != L'\\' || volume_name[ 2 ] != L'?' || volume_name[ 3 ] != L'\\' || volume_name[ index ] != L'\\' )
			break;
		volume_name[ index ] = L'\0';
		auto char_count = QueryDosDeviceW( &volume_name[ 4 ], device_name, ARRAYSIZE( device_name ) );
		volume_name[ index ] = L'\\';
		if ( char_count == 0 )
			break;
		wchar_t driver_letter[ MAX_PATH + 1 ];
		if ( GetVolumePathNamesForVolumeNameW( volume_name, driver_letter, MAX_PATH, &char_count ) )
			vol_info.push_back( { driver_letter , std::wstring( device_name ) + L"\\" } );

	} while ( FindNextVolumeW( h_find, volume_name, ARRAYSIZE( volume_name ) ) );
	FindVolumeClose( h_find );
	return;
}


std::wstring utils::str_replace( std::wstring str, const std::wstring& from, const std::wstring& to )
{
	size_t start_pos = 0;
	while ( ( start_pos = str.find( from, start_pos ) ) != std::wstring::npos )
	{
		str.replace( start_pos, from.length( ), to );
		start_pos += to.length( ); // Handles case where 'to' is a substring of 'from'
	}
	return str;
}

std::wstring utils::remove_device( std::wstring device_path )
{
	if ( vol_info.empty( ) )
		update_volumes_info( );
	for ( auto info : vol_info )
	{
		if ( device_path.find( info.vol_device ) != std::wstring::npos )
			return str_replace( device_path, info.vol_device, info.letter );
	}
	return device_path;
}

bool utils::open_bin_file( const std::wstring& file, std::vector<uint8_t>& data )
{
	std::ifstream file_stream( file, std::ios::binary );
	if ( file_stream.fail( ) )
		return false;
	file_stream.unsetf( std::ios::skipws );
	file_stream.seekg( 0, std::ios::end );

	const auto file_size = file_stream.tellg( );

	file_stream.seekg( 0, std::ios::beg );
	data.reserve( static_cast<uint32_t>( file_size ) );
	data.insert( data.begin( ), std::istream_iterator<uint8_t>( file_stream ), std::istream_iterator<uint8_t>( ) );
	file_stream.close( );
	return !data.empty( );
}