#[path = "../../../tests/leak/src/native_browser_fixture.rs"]
mod fixture;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    fixture::run()
}
