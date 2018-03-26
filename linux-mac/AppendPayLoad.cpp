// AppendPayLoad.cpp
//
// Changing a Signed Executable Without Altering Windows Digital Signature
// https://blog.barthe.ph/2009/02/22/change-signed-executable/
//
// Author:
//      Aymeric Barthe <aymeric@barthe.ph> - Original author (2009)
//      Jason Klein <jrklein@jrklein.com> - Ported to Linux/OSX (2018)

#include <exception>
#include <iostream>
#include <fstream>

#ifndef DWORD
typedef unsigned int       DWORD;
#endif 

#ifndef ASSERT
#define ASSERT(exp) if (!(exp)) throw std::runtime_error("Assertion failed");
#endif 

std::string g_input_file;
std::string g_payload_file;
std::string g_output_file;

void showHelp()
{
	std::cerr << std::endl;
	std::cerr << "Syntax: AppendPayLoad.exe input_file payload_file output_file" << std::endl;
	std::cerr << "Usage: Append payload at the end of input file." << std::endl << "The result is stored in output_file" << std::endl;
	std::cerr << std::endl;
}

bool parseParameters(int argc, char* argv[])
{
	if (argc != 4)
	{
		std::cerr << "Syntax Error: Invalid number of parameters" << std::endl;
		showHelp();
		return false;
	}
	g_input_file = argv[1];
	g_payload_file = argv[2];
	g_output_file = argv[3];

	return true;
}

void addPayload(std::istream& in_stream, std::istream& payload_stream, std::ostream& out_stream)
{
	const int CERTIFICATE_ENTRY_OFFSET = 148;
	const int PAYLOAD_ALIGNMENT = 8;
	
	// Get stream buffers
	std::streambuf* in = in_stream.rdbuf();
	std::streambuf* payload = payload_stream.rdbuf();
	std::streambuf* out = out_stream.rdbuf();
	ASSERT(in && payload && out);

	// Machine check... quick&dirty
	{
		if (sizeof(DWORD) != 4)
			throw std::runtime_error("Machine not supported. Wrong DWORD size.");
		char buf[4] = { 1, 0, 0, 0 };
		if (*(reinterpret_cast<DWORD*>(buf)) != 1)
			throw std::runtime_error("Machine not supported. Because it is BigEndian.");
	}

	// Get PE\0\0 Header signature
	while(in->sgetc() != EOF)
	{
		char c1 = in->sbumpc();
		if (c1 == 'P')
		{
			char c2 = in->sbumpc();
			if (c2 == 'E')
			{
				char c3 = in->sbumpc();
				if (c3 == '\0')
				{
					char c4 = in->sbumpc();
					if (c4 == '\0')
						break;
				}
			}
		}
	}
	if (in->sgetc() == EOF)
		throw std::runtime_error("Input is not a valid PE Executable");

	// Skip COFF header and go to Windows optional header, to read the certificate entry section
	DWORD cert_table_offset = 0;
	DWORD cert_table_length = 0;
	in->pubseekoff(CERTIFICATE_ENTRY_OFFSET, std::ios::cur);
	in->sgetn(reinterpret_cast<char*>(&cert_table_offset), 4);
	const std::streamoff cert_table_length_offset = in->pubseekoff(0, std::ios::cur);
	in->sgetn(reinterpret_cast<char*>(&cert_table_length), 4);
	
	// Read Certificate table and check it is possible to add payload
	in->pubseekpos(cert_table_offset);
	DWORD cert_table_length2 = 0;
	in->sgetn(reinterpret_cast<char*>(&cert_table_length2), 4);
	if (cert_table_length != cert_table_length2)
		throw std::runtime_error("Failed to read certificate table location properly");
	if (cert_table_offset + cert_table_length != in->pubseekoff(0, std::ios::end))
		throw std::runtime_error("The certificate table is not located at the end of the file!");

	// Copy input into output
	const int buf_size = 8192;
	char* buffer = new char[buf_size];	// known leak!!
	in->pubseekpos(0);
	std::streamsize bytes_read = 0;
	do {
		bytes_read = in->sgetn(buffer, buf_size);
		out->sputn(buffer, bytes_read);
	} while (in->sgetc() != EOF);
	DWORD payload_size = 0;
	do {
		bytes_read = payload->sgetn(buffer, buf_size);
		payload_size += bytes_read;
		out->sputn(buffer, bytes_read);
	} while (payload->sgetc() != EOF);
	
	// Padding of payload
	const int padding_size = PAYLOAD_ALIGNMENT - (payload_size % PAYLOAD_ALIGNMENT);
	if (padding_size > 0)
	{
		for (int i=0; i<padding_size; ++i)
			out->sputc(0);
	}

	// Update certification table
	cert_table_length = cert_table_length + payload_size + padding_size;
	out->pubseekpos(cert_table_length_offset);
	out->sputn(reinterpret_cast<char*>(&cert_table_length), sizeof(DWORD));
	out->pubseekpos(cert_table_offset);
	out->sputn(reinterpret_cast<char*>(&cert_table_length), sizeof(DWORD));
}

int main(int argc, char* argv[])
{

	try {
		// Parse cmd line parameters
		if (!parseParameters(argc, argv))
			return -1;

		// Create file streams
		std::ifstream input_file(g_input_file.c_str(), std::ios::binary|std::ios::in);
		if (input_file.fail() || input_file.bad())
			throw std::runtime_error("Cannot open input file");
		std::ifstream payload_file(g_payload_file.c_str(), std::ios::binary|std::ios::in);
		if (payload_file.fail() || payload_file.bad())
			throw std::runtime_error("Cannot open payload file");
		std::ofstream output_file(g_output_file.c_str(), std::ios::binary|std::ios::out);
		if (output_file.fail() || output_file.bad())
			throw std::runtime_error("Cannot create output file");

		// Set up exception throwing
		input_file.exceptions(std::ios::eofbit|std::ios::failbit|std::ios::badbit);
		payload_file.exceptions(std::ios::eofbit|std::ios::failbit|std::ios::badbit);
		output_file.exceptions(std::ios::failbit|std::ios::badbit);

		// Append payload
		addPayload(input_file, payload_file, output_file);
	} 

	catch (std::exception& err)
	{
		std::cerr << "I/O Error: " << err.what() << std::endl;
		return -2;
	}

	return 0;
}

