fn main() {
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CXX");
    println!("cargo:rerun-if-changed=vendor/bitcoin-core-v31.1/sha256_avx2.cpp");
    println!("cargo:rerun-if-changed=src/wrapper.cpp");
    println!("cargo:rerun-if-changed=include/attributes.h");
    println!("cargo:rerun-if-changed=include/crypto/common.h");
    println!("cargo:rustc-check-cfg=cfg(avila_sha256d64_avx2)");

    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64") {
        return;
    }

    cc::Build::new()
        .cpp(true)
        .std("c++20")
        .define("ENABLE_AVX2", None)
        .include("include")
        .flag_if_supported("-mavx2")
        .flag_if_supported("/arch:AVX2")
        .file("vendor/bitcoin-core-v31.1/sha256_avx2.cpp")
        .file("src/wrapper.cpp")
        .compile("avila_sha256d64_avx2");

    println!("cargo:rustc-cfg=avila_sha256d64_avx2");
}
