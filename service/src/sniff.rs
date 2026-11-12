//! Extract the requested hostname from the first bytes of a connection, without terminating
//! anything: TLS ClientHello (SNI), HTTP/1.x (Host header) and the Minecraft Java handshake.

#[derive(Debug, PartialEq, Eq)]
pub enum Sniffed {
    /// A protocol we understand, with the (lowercased) hostname the client asked for.
    Host(String),
    /// A protocol we understand, but it carried no hostname.
    NoHost,
    /// Not enough bytes yet to decide.
    NeedMore,
    /// Not a protocol we understand.
    Unknown,
}

pub fn sniff(b: &[u8]) -> Sniffed {
    if b.is_empty() {
        return Sniffed::NeedMore;
    }
    let parsers: [fn(&[u8]) -> Sniffed; 3] = [tls_sni, http_host, mc_host];
    for p in parsers {
        match p(b) {
            Sniffed::Unknown => continue,
            other => return other,
        }
    }
    Sniffed::Unknown
}

fn host_result(h: &str) -> Sniffed {
    let h = h.split('\0').next().unwrap_or("");
    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        Sniffed::NoHost
    } else {
        Sniffed::Host(h)
    }
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

enum VarErr {
    Trunc,
    Bad,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.p
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Some(s)
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn u24(&mut self) -> Option<u32> {
        self.take(3).map(|s| u32::from_be_bytes([0, s[0], s[1], s[2]]))
    }
    fn varint(&mut self) -> Result<u32, VarErr> {
        let mut v: u32 = 0;
        for i in 0..5 {
            let b = self.u8().ok_or(VarErr::Trunc)?;
            v |= ((b & 0x7f) as u32) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(VarErr::Bad)
    }
}

// ---- TLS ----------------------------------------------------------------------------

fn tls_sni(b: &[u8]) -> Sniffed {
    if b[0] != 0x16 {
        return Sniffed::Unknown;
    }
    if b.len() < 5 {
        return Sniffed::NeedMore;
    }
    if b[1] != 3 || b[2] > 4 {
        return Sniffed::Unknown;
    }
    let rec = u16::from_be_bytes([b[3], b[4]]) as usize;
    if rec == 0 || rec > 16384 + 2048 {
        return Sniffed::Unknown;
    }
    let complete = b.len() >= 5 + rec;
    let body = &b[5..b.len().min(5 + rec)];
    match parse_client_hello(body) {
        Some(Some(h)) => host_result(&h),
        Some(None) => Sniffed::NoHost,
        None if complete => Sniffed::NoHost,
        None => Sniffed::NeedMore,
    }
}

/// `None` = ran out of bytes. `Some(None)` = parsed, no server_name.
fn parse_client_hello(b: &[u8]) -> Option<Option<String>> {
    let mut r = Reader::new(b);
    if r.u8()? != 1 {
        return Some(None); // not a ClientHello
    }
    r.u24()?; // handshake length
    r.skip(2 + 32)?; // version + random
    let sid = r.u8()? as usize;
    r.skip(sid)?;
    let cs = r.u16()? as usize;
    r.skip(cs)?;
    let cm = r.u8()? as usize;
    r.skip(cm)?;
    let ext_total = r.u16()? as usize;
    let mut ext = Reader::new(r.take(ext_total)?);
    while ext.remaining() > 0 {
        let ty = ext.u16()?;
        let len = ext.u16()? as usize;
        let data = ext.take(len)?;
        if ty == 0 {
            let mut d = Reader::new(data);
            d.u16()?; // list length
            while d.remaining() > 0 {
                let name_type = d.u8()?;
                let nl = d.u16()? as usize;
                let name = d.take(nl)?;
                if name_type == 0 {
                    return Some(std::str::from_utf8(name).ok().map(str::to_string));
                }
            }
            return Some(None);
        }
    }
    Some(None)
}

// ---- HTTP/1.x -----------------------------------------------------------------------

const METHODS: [&[u8]; 9] = [
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
];
const MAX_HTTP_HEAD: usize = 8192;

fn http_host(b: &[u8]) -> Sniffed {
    if !METHODS.iter().any(|m| b.starts_with(m) || m.starts_with(b)) {
        return Sniffed::Unknown;
    }
    let end = match b.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i,
        None if b.len() >= MAX_HTTP_HEAD => return Sniffed::NoHost,
        None => return Sniffed::NeedMore,
    };
    let head = String::from_utf8_lossy(&b[..end]);
    for line in head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("host") {
                return host_result(strip_port(value.trim()));
            }
        }
    }
    Sniffed::NoHost
}

fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match h.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) => host,
        _ => h,
    }
}

// ---- Minecraft Java handshake ---------------------------------------------------------

fn mc_host(b: &[u8]) -> Sniffed {
    macro_rules! var {
        ($r:expr) => {
            match $r.varint() {
                Ok(v) => v,
                Err(VarErr::Trunc) => return Sniffed::NeedMore,
                Err(VarErr::Bad) => return Sniffed::Unknown,
            }
        };
    }
    let mut r = Reader::new(b);
    let len = var!(r) as usize;
    if len == 0 || len > 1200 {
        return Sniffed::Unknown;
    }
    if var!(r) != 0 {
        return Sniffed::Unknown; // packet id 0x00 = handshake
    }
    var!(r); // protocol version
    let slen = var!(r) as usize;
    if slen == 0 || slen > 1000 {
        return Sniffed::Unknown;
    }
    let Some(addr) = r.take(slen) else {
        return Sniffed::NeedMore;
    };
    if r.take(2).is_none() {
        return Sniffed::NeedMore; // port
    }
    let next = var!(r);
    if !(1..=3).contains(&next) {
        return Sniffed::Unknown;
    }
    match std::str::from_utf8(addr) {
        Ok(h) => host_result(h),
        Err(_) => Sniffed::Unknown,
    }
}

#[doc(hidden)]
pub mod testutil {
    //! Builders for synthetic first-packets, shared with the integration tests.

    pub fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(name) = sni {
            let n = name.as_bytes();
            let mut sn = Vec::new();
            sn.push(0u8);
            sn.extend((n.len() as u16).to_be_bytes());
            sn.extend(n);
            let mut data = Vec::new();
            data.extend((sn.len() as u16).to_be_bytes());
            data.extend(sn);
            ext.extend(0u16.to_be_bytes());
            ext.extend((data.len() as u16).to_be_bytes());
            ext.extend(data);
        }
        // supported_versions, so the hello isn't trivially tiny
        ext.extend([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        let mut hs = Vec::new();
        hs.extend([0x03, 0x03]);
        hs.extend([7u8; 32]);
        hs.push(0);
        hs.extend(2u16.to_be_bytes());
        hs.extend([0x13, 0x01]);
        hs.push(1);
        hs.push(0);
        hs.extend((ext.len() as u16).to_be_bytes());
        hs.extend(ext);
        let mut body = vec![1u8];
        body.extend(&(hs.len() as u32).to_be_bytes()[1..]);
        body.extend(hs);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend((body.len() as u16).to_be_bytes());
        rec.extend(body);
        rec
    }

    fn varint(mut v: u32, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    pub fn mc_handshake(host: &str, next_state: u32) -> Vec<u8> {
        let mut p = Vec::new();
        varint(0, &mut p);
        varint(765, &mut p);
        varint(host.len() as u32, &mut p);
        p.extend(host.as_bytes());
        p.extend(25565u16.to_be_bytes());
        varint(next_state, &mut p);
        let mut out = Vec::new();
        varint(p.len() as u32, &mut out);
        out.extend(p);
        out
    }

    pub fn http_request(host: &str) -> Vec<u8> {
        format!("GET / HTTP/1.1\r\nUser-Agent: t\r\nHost: {host}\r\nAccept: */*\r\n\r\n").into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    #[test]
    fn tls_sni_is_extracted() {
        let hello = client_hello(Some("Blog.Example.COM"));
        assert_eq!(sniff(&hello), Sniffed::Host("blog.example.com".into()));
    }

    #[test]
    fn tls_without_sni() {
        assert_eq!(sniff(&client_hello(None)), Sniffed::NoHost);
    }

    #[test]
    fn tls_truncated_needs_more_at_every_prefix() {
        let hello = client_hello(Some("a.example.com"));
        for n in 1..hello.len() {
            assert_eq!(sniff(&hello[..n]), Sniffed::NeedMore, "prefix {n}");
        }
        assert!(matches!(sniff(&hello), Sniffed::Host(_)));
    }

    #[test]
    fn http_host_header() {
        assert_eq!(sniff(&http_request("Site.Example.com:8080")), Sniffed::Host("site.example.com".into()));
        assert_eq!(sniff(&http_request("[::1]:80")), Sniffed::Host("::1".into()));
    }

    #[test]
    fn http_partial_then_complete() {
        let req = http_request("a.example.com");
        for n in 1..req.len() {
            assert_eq!(sniff(&req[..n]), Sniffed::NeedMore, "prefix {n}");
        }
        assert_eq!(sniff(&req), Sniffed::Host("a.example.com".into()));
    }

    #[test]
    fn http_without_host_is_nohost() {
        assert_eq!(sniff(b"GET / HTTP/1.0\r\n\r\n"), Sniffed::NoHost);
    }

    #[test]
    fn minecraft_handshake_host() {
        let hs = mc_handshake("Survival.Example.com", 2);
        assert_eq!(sniff(&hs), Sniffed::Host("survival.example.com".into()));
        // Forge appends \0FML\0
        let hs = mc_handshake("play.example.com\0FML\0", 2);
        assert_eq!(sniff(&hs), Sniffed::Host("play.example.com".into()));
    }

    #[test]
    fn minecraft_truncated_needs_more() {
        let hs = mc_handshake("play.example.com", 1);
        for n in 1..hs.len() {
            assert_eq!(sniff(&hs[..n]), Sniffed::NeedMore, "prefix {n}");
        }
    }

    #[test]
    fn other_protocols_are_unknown() {
        assert_eq!(sniff(b"SSH-2.0-OpenSSH_9.6\r\n"), Sniffed::Unknown);
        assert_eq!(sniff(b"\x05\x01\x00\x00"), Sniffed::Unknown);
        assert_eq!(sniff(b"+OK\r\n"), Sniffed::Unknown);
    }

    #[test]
    fn empty_is_need_more() {
        assert_eq!(sniff(b""), Sniffed::NeedMore);
    }
}
