use crate::Result;
use tokio::net::TcpListener;

#[derive(Debug)]
pub enum Port {
    TryExplicitOrRandom(u16),
    Explicit(u16),
}

impl Port {
    pub async fn bind_to_tcp_listener(&self) -> Result<TcpListener> {
        match self {
            Self::TryExplicitOrRandom(port) => {
                // Try to bind to the explicit port
                match TcpListener::bind(&format!("127.0.0.1:{port}")).await {
                    Ok(listener) => Ok(listener),
                    Err(err) => {
                        // If the port is already in use, bind to a random port
                        if err.kind() == std::io::ErrorKind::AddrInUse {
                            Ok(TcpListener::bind("127.0.0.1:0").await?)
                        } else {
                            Err(err.into())
                        }
                    }
                }
            }
            // If explicit, try to bind to that port or fail
            Self::Explicit(port) => Ok(TcpListener::bind(&format!("127.0.0.1:{port}")).await?),
        }
    }
}
