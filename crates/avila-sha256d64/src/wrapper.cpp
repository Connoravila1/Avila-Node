namespace sha256d64_avx2 {
void Transform_8way(unsigned char* out, const unsigned char* in);
}

extern "C" void avila_sha256d64_8way(unsigned char* out, const unsigned char* in)
{
    sha256d64_avx2::Transform_8way(out, in);
}
