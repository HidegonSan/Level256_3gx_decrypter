#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>

using uint = unsigned int;

void decrypt(uint* output, const uint* input, uint size) {

    uint i;

    // inverse bits
    for (i = 0; size >> 2 != i; i++) {
        output[i] = ~input[i];
    }

    // Key
    const uint TMP_DIFF_KEY    = 0x63DA901F;
    const uint XOR_KEY  = 0x480C9A12;
    const int DIFF_KEY  = 0x5AE007DF;

    // tmp
    uint *file_ptr  = output - 1;
    uint pre_key      = 0x63DA901F;
    uint tmp_key      = 0x63DA901F;

    // decryption
    for (uint j = 0; j < i; j++) {
        uint raw = *(++file_ptr);
        uint tmp = pre_key + TMP_DIFF_KEY;
        pre_key += (raw ^ XOR_KEY);
        *file_ptr = (tmp_key ^ raw) ^ (j * (tmp_key + DIFF_KEY));
        tmp_key = tmp ^ raw;
    }

}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Level256 Network 3GX Decrypter by Hidegon <3" << std::endl;
        std::cout << "Usage: " << argv[0] << " <encrypted file name> <output file name>" << std::endl;
        return 1;
    }

    std::ifstream encrypted_file(argv[1], std::ios::binary | std::ios::ate);
    if (!encrypted_file) {
        std::cerr << "Could not open the encrypted file: " << argv[1] << std::endl;
        return 1;
    }

    std::streamsize file_size = encrypted_file.tellg();
    encrypted_file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(file_size);
    if (!encrypted_file.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
        std::cerr << "Could not read encrypted file." << std::endl;
        return 1;
    }

    // Start address of the code section
    const uint32_t code_offset = 0x240;

    // Get size of the code section
    uint32_t code_size;
    std::memcpy(&code_size, &buffer[0x5C], sizeof(code_size));

    // Creating buffer wich store the code section
    if (code_offset + code_size > buffer.size()) {
        std::cerr << "Could not read the code section" << std::endl;
        return 1;
    }

    // Read and decrypt the code section
    std::vector<uint> input_code(code_size / 4);
    std::memcpy(input_code.data(), &buffer[code_offset], code_size);

    std::vector<uint> output_code(code_size / 4);
    decrypt(output_code.data(), input_code.data(), code_size);

    // Replace the encrypted code section with the decrypted one
    std::memcpy(&buffer[code_offset], output_code.data(), code_size);


    std::ofstream decrypted_file(argv[2], std::ios::binary);
    if (!decrypted_file.write(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
        std::cerr << "ailed to write the decrypted data." << std::endl;
        return 1;
    }

    std::cout << "Success!" << std::endl;
    return 0;
}
