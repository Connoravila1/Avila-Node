fn main() {
    let dir = std::path::Path::new("/home/connoravila/Documents/Avila-Node/data/mainnet");
    let be = avila_consensus::coinsdb::CoinsBackend::open(dir).unwrap();
    eprintln!(
        "tip_height={} coins_len={} is_empty={}",
        be.tip_height(),
        be.coins_len(),
        be.is_fresh()
    );
}
