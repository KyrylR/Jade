use alloc::{
    string::{String, ToString},
    vec::Vec,
};

pub const MAX_PATH_LEN: usize = 16;
pub const HARDENED_BIT: u32 = 1 << 31;
pub const MAX_UNHARDENED_CHILD: u32 = HARDENED_BIT - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JadeDerivationPath {
    parts: Vec<u32>,
}

impl JadeDerivationPath {
    pub fn parse(path: &str) -> Result<Self, PathError> {
        let mut rest = path;
        if let Some(stripped) = rest.strip_prefix("m/").or_else(|| rest.strip_prefix("M/")) {
            rest = stripped;
        } else if rest == "m" || rest == "M" {
            return Err(PathError::Empty);
        }

        if rest.is_empty() {
            return Err(PathError::Empty);
        }

        let mut parts = Vec::new();
        for segment in rest.split('/') {
            if segment.is_empty() {
                return Err(PathError::InvalidSyntax);
            }
            if parts.len() == MAX_PATH_LEN {
                return Err(PathError::TooLong);
            }
            parts.push(parse_segment(segment)?);
        }
        Self::from_u32(&parts)
    }

    pub fn from_u32(path: &[u32]) -> Result<Self, PathError> {
        if path.is_empty() {
            return Err(PathError::Empty);
        }
        if path.len() > MAX_PATH_LEN {
            return Err(PathError::TooLong);
        }
        Ok(Self {
            parts: path.to_vec(),
        })
    }

    pub fn as_u32_slice(&self) -> &[u32] {
        &self.parts
    }

    pub fn to_u32_vec(&self) -> Vec<u32> {
        self.parts.clone()
    }

    pub fn to_jade_string(&self, path_only: bool) -> String {
        let mut out = String::new();
        if !path_only {
            out.push('m');
        }
        for (index, part) in self.parts.iter().copied().enumerate() {
            if !path_only || index > 0 {
                out.push('/');
            }
            out.push_str(&(part & !HARDENED_BIT).to_string());
            if is_hardened(part) {
                out.push('\'');
            }
        }
        out
    }

    pub fn unhardened_tail_index(&self) -> usize {
        self.parts
            .iter()
            .rposition(|part| is_hardened(*part))
            .map(|index| index + 1)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    Empty,
    TooLong,
    InvalidSyntax,
    InvalidChildNumber,
}

pub fn harden(index: u32) -> Result<u32, PathError> {
    if index > MAX_UNHARDENED_CHILD {
        return Err(PathError::InvalidChildNumber);
    }
    Ok(index | HARDENED_BIT)
}

pub fn is_hardened(index: u32) -> bool {
    index & HARDENED_BIT != 0
}

fn parse_segment(segment: &str) -> Result<u32, PathError> {
    let (number, hardened) = match segment.as_bytes().last().copied() {
        Some(b'h' | b'H' | b'\'') => (&segment[..segment.len() - 1], true),
        Some(_) => (segment, false),
        None => return Err(PathError::InvalidSyntax),
    };
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PathError::InvalidSyntax);
    }

    let index = number
        .parse::<u32>()
        .map_err(|_| PathError::InvalidChildNumber)?;
    if index > MAX_UNHARDENED_CHILD {
        return Err(PathError::InvalidChildNumber);
    }

    if hardened {
        Ok(index | HARDENED_BIT)
    } else {
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parses_and_formats_jade_paths() {
        let path = JadeDerivationPath::parse("m/84h/0H/0'/0/5").unwrap();

        assert_eq!(
            path.to_u32_vec(),
            vec![84 | HARDENED_BIT, HARDENED_BIT, HARDENED_BIT, 0, 5]
        );
        assert_eq!(path.to_jade_string(false), "m/84'/0'/0'/0/5");
        assert_eq!(path.to_jade_string(true), "84'/0'/0'/0/5");
        assert_eq!(path.unhardened_tail_index(), 3);
    }

    #[test]
    fn builds_from_wire_u32_values() {
        let path = JadeDerivationPath::from_u32(&[
            48 | HARDENED_BIT,
            HARDENED_BIT,
            HARDENED_BIT,
            2 | HARDENED_BIT,
            0,
            9,
        ])
        .unwrap();

        assert_eq!(path.to_jade_string(false), "m/48'/0'/0'/2'/0/9");
        assert_eq!(path.as_u32_slice()[5], 9);
    }

    #[test]
    fn rejects_empty_or_oversized_paths() {
        assert_eq!(JadeDerivationPath::from_u32(&[]), Err(PathError::Empty));
        assert_eq!(JadeDerivationPath::parse("m"), Err(PathError::Empty));

        let too_long = [0u32; MAX_PATH_LEN + 1];
        assert_eq!(
            JadeDerivationPath::from_u32(&too_long),
            Err(PathError::TooLong)
        );
    }

    #[test]
    fn rejects_invalid_syntax_and_child_numbers() {
        assert_eq!(
            JadeDerivationPath::parse("m/0//1"),
            Err(PathError::InvalidSyntax)
        );
        assert_eq!(
            JadeDerivationPath::parse("m/not-a-number"),
            Err(PathError::InvalidSyntax)
        );
        assert_eq!(
            JadeDerivationPath::parse("m/2147483648"),
            Err(PathError::InvalidChildNumber)
        );
        assert_eq!(harden(HARDENED_BIT), Err(PathError::InvalidChildNumber));
    }
}
