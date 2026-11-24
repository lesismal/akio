use super::*;

/// Hashes made by Go's `bcrypt.GenerateFromPassword` (`$2a$`) and Apache's `htpasswd -B`
/// (`$2y$`), and OpenBSD's test vector.
const VECTORS: &[(&[u8], &str)] = &[
    (
        b"",
        "$2a$04$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC26",
    ),
    (
        b"pw",
        "$2a$05$mWYMOspQSNd/VOVpYnQb4uihAoVqS2EvcJiAcLbM.64XhaZ.FEJIS",
    ),
    (
        b"wonderland",
        "$2a$06$6K0itQDfc2BNr3J5u65Jpuq3CLNO0j.nDndXeDq0NGY.m6NvWgTs.",
    ),
    (
        b"builder",
        "$2a$04$xFZtrtlKOY9JUcFCMP7O9Opk0hM1JvxWzgZxgwmPRmjIGuSazoOIO",
    ),
    (
        "h\u{e9}llo w\u{f6}rld".as_bytes(),
        "$2a$05$L0oX3Z42JEwdNvOqrIb4HuTn9/d2A1LoDImHoten2OmSC0WN2wkhq",
    ),
    (
        b"U*U",
        "$2a$04$IE1/gkUrc3OPaHKwzwuHMeqKYjMGQvhvYn9vaA7tRkJuIh7SMnFlS",
    ),
    (
        b"\0nul",
        "$2a$05$fu4qXeK4JaYYb8NvS5RsDOcxt1vQjll2aeFbprgjr3yatgx8Vpgoe",
    ),
    (
        b"pw",
        "$2y$05$skiZk0SnUJNo2I6tAYj.FOJd7NKP44JQaF889.YEyBr7g/uf47whC",
    ),
    (
        b"tea pot",
        "$2y$05$0JYi/nZY.cTUu3BG2/vQ8Oiqb4sA9vDwLe4VGoM9KcB49eQNRClby",
    ),
    (
        b"U*U",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
    ),
];

#[test]
fn vectors() {
    for (password, hash) in VECTORS {
        let h = Hash::parse(hash).unwrap();
        assert!(h.verify(password), "{password:?} {hash}");
        let mut wrong = password.to_vec();
        wrong.push(b'x');
        assert!(!h.verify(&wrong), "{password:?}+x {hash}");
        assert_eq!(h.to_string(), *hash, "written back as it was");
    }
}

#[test]
fn hashes_reproduced_from_their_salt() {
    for (password, hash) in VECTORS {
        let h = Hash::parse(hash).unwrap();
        let again = hash_with_salt(password, h.cost(), &h.salt).unwrap();
        // Made as $2b$; the rest is the same.
        assert_eq!(again[4..], hash[hash.len() - 56..], "{password:?}");
        assert!(again.starts_with("$2b$"));
    }
}

#[test]
fn made_and_checked() {
    let h = hash(b"secret", MIN_COST).unwrap();
    assert!(h.starts_with("$2b$04$") && h.len() == 60);
    let p = Hash::parse(&h).unwrap();
    assert!(p.verify(b"secret") && !p.verify(b"secreT"));
    assert_ne!(
        hash(b"secret", MIN_COST).unwrap(),
        h,
        "a random salt each time"
    );
    assert_eq!(hash(&[b'a'; 73], MIN_COST), Err(Error::InvalidLength));
    assert_eq!(hash(b"a", 3), Err(Error::InvalidLength));
    assert_eq!(hash(b"a", 32), Err(Error::InvalidLength));
    assert!(hash(&[b'a'; 72], MIN_COST).is_ok());
}

/// Go checks a password past 72 bytes by its first 72.
#[test]
fn long_passwords() {
    let h = Hash::parse("$2a$06$szMwsggOOlOzNjd0v0VN8.0Kfe3Cp8O2p9h5.0Is5ilBpVLgNb9/q").unwrap();
    assert!(h.verify(&[b'a'; 72]));
    assert!(h.verify(&[b'a'; 73]));
    assert!(!h.verify(&[b'a'; 71]));
}

#[test]
fn not_hashes() {
    let good = "$2a$04$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC26";
    assert_eq!(Hash::parse(good).unwrap().cost(), 4);
    for (bad, why) in [
        ("pw", ParseError::Prefix),
        ("", ParseError::Prefix),
        (
            "$2c$04$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC26",
            ParseError::Prefix,
        ),
        (
            "$1$04$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC26",
            ParseError::Prefix,
        ),
        ("$2a$04$", ParseError::Encoding),
        (
            "$2a$03$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC26",
            ParseError::Cost,
        ),
        (
            "$2a$32$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC26",
            ParseError::Cost,
        ),
        (
            "$2a$4$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC26",
            ParseError::Cost,
        ),
        (
            "$2a$04$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC2",
            ParseError::Encoding,
        ),
        (
            "$2a$04$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC26x",
            ParseError::Encoding,
        ),
        (
            "$2a$04$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC2=",
            ParseError::Encoding,
        ),
        (
            "$2a$04$5xt5UjNNUVWTqOgf9FDZm.bfWVyXg.U2as/rOFV.Ny5IQstc/jC2\u{e9}",
            ParseError::Encoding,
        ),
    ] {
        assert_eq!(Hash::parse(bad), Err(why), "{bad:?}");
    }
    // Bits past the salt's 16 bytes are ignored, as Go ignores them.
    let odd = "$2a$04$5xt5UjNNUVWTqOgf9FDZm/bfWVyXg.U2as/rOFV.Ny5IQstc/jC26";
    let h = Hash::parse(odd).unwrap();
    assert!(h.verify(b""));
    assert_eq!(h.to_string(), good);
}
