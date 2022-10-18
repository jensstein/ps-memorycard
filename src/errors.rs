#[derive(Debug, Clone)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: String) -> Self {
        Self {message}
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::array::TryFromSliceError> for Error {
    fn from(error: std::array::TryFromSliceError) -> Self {
        Self::new(format!("Unable to read bytes: {}", error))
    }
}

impl From<rusb::Error> for Error {
    fn from(error: rusb::Error) -> Self {
        Self::new(format!("Unable to read from usb device: {}", error))
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::new(format!("Error when reading from disk: {}", error))
    }
}

impl From<Vec<u8>> for Error {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(format!("Unable to handle bytes {:?}", bytes))
    }
}

impl From<CryptographyError> for Error {
    fn from(error: CryptographyError) -> Self {
        Self {message: format!("Error when de- or encrypting: {}", error)}
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self::new(message.into())
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

#[derive(Debug, Clone)]
pub struct CryptographyError {
    message: String,
}

impl CryptographyError {
    pub fn new(message: String) -> Self {
        Self {message}
    }
}

impl std::fmt::Display for CryptographyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.message)
    }
}

impl From<cbc::cipher::inout::PadError> for CryptographyError {
    fn from(error: cbc::cipher::inout::PadError) -> Self {
        Self::new(format!("Incorrect padding when encrypting: {}", error))
    }
}

impl From<cbc::cipher::block_padding::UnpadError> for CryptographyError {
    fn from(error: cbc::cipher::block_padding::UnpadError) -> Self {
        Self::new(format!("Incorrect padding when decrypting: {}", error))
    }
}
