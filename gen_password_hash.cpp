#include <crypt.h>
#include <stdio.h>

#include <random>

const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int main(int argc, char **argv)
{
    std::string salt("$6$");
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, 63);

    for (unsigned int i = 0; i < 16; i++)
        salt += base64_chars[dist(rng)];
    printf("Salt: %s\n", salt.c_str());
    printf("crypt: %s\n", crypt(argv[1], salt.c_str()));
}
