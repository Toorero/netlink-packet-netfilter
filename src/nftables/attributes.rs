use netlink_packet_core::{
    emit_u32_be, parse_u32_be, DecodeError, DefaultNla, Emitable, ErrorContext,
    Nla, NlaBuffer, NlasIterator, Parseable,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NfTablesAttribute {
    Other(DefaultNla),
}

impl Nla for NfTablesAttribute {
    fn value_len(&self) -> usize {
        match self {
            NfTablesAttribute::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            NfTablesAttribute::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            NfTablesAttribute::Other(attr) => attr.emit_value(buffer),
        }
    }
    fn is_nested(&self) -> bool {
        false
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>>
    for NfTablesAttribute
{
    fn parse(buf: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let kind = buf.kind();
        let payload = buf.value();
        let nla = match kind {
            _ => NfTablesAttribute::Other(DefaultNla::parse(buf)?),
        };
        Ok(nla)
    }
}
