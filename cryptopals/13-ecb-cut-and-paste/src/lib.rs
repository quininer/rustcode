extern crate url;
extern crate byte_at_a_time_ecb_decryption_simple;

use std::collections::HashMap;
use url::form_urlencoded;

/// ```
/// use ecb_cut_and_paste::parse_profile;
/// assert_eq!(
///     parse_profile("email=foo@bar.com&uid=10&role=user").get("email"),
///     Some(&"foo@bar.com".to_string())
/// );
/// ```
pub fn parse_profile<D: AsRef<[u8]>>(profile: D) -> HashMap<String, String> {
    form_urlencoded::parse(profile.as_ref()).iter()
        .cloned()
        .collect()
}

/// ```
/// use ecb_cut_and_paste::profile_for;
/// assert_eq!(
///     profile_for("foo@bar.com"),
///     "email=foo@bar.com&uid=10&role=user"
/// )
/// ```
pub fn profile_for<D: AsRef<[u8]>>(input: D) -> String {
    // Do not use form_urlencoded::serialize, because format.
    format!(
        "email={}&uid=10&role=user",
        String::from_utf8_lossy(input.as_ref())
            .replace('&', "%26")
            .replace('=', "%3d")
    )
}

#[test]
fn it_works() {
    use byte_at_a_time_ecb_decryption_simple::Oracle;

    let oracle = Oracle::new(&[], &[]);
    let cipher = oracle.encryption(
        profile_for("foo@bar.cradmin+++++++++++ypt").as_ref()
    );
    let pdata = oracle.decryption(&[
        &cipher[..16],
        &cipher[32..48],
        &cipher[16..32],
        &[&[0; 4], &cipher[48..60]].concat()
    ].concat());
    let profile = parse_profile(pdata);

    assert_eq!(
        profile.get("role").map(|r| r.trim()),
        Some("admin")
    );
    assert_eq!(
        profile.get("email"),
        Some(&String::from("foo@bar.crypt"))
    );
    assert_eq!(
        profile.get("uid"),
        Some(&String::from("10"))
    );
}
