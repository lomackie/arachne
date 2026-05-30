use std::collections::HashMap;
use std::env;
use super::error::CniError;

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Add,
    Del,
    Check,
    Version,
    Gc,
    Status,
}

impl std::str::FromStr for Command {
    type Err = CniError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ADD" => Ok(Command::Add),
            "DEL" => Ok(Command::Del),
            "CHECK" => Ok(Command::Check),
            "VERSION" => Ok(Command::Version),
            "GC" => Ok(Command::Gc),
            "STATUS" => Ok(Command::Status),
            other => Err(CniError::InvalidEnv(format!("unknown CNI_COMMAND: {other}"))),
        }
    }
}

#[derive(Debug)]
pub struct CniParams {
    pub command: Command,
    pub container_id: Option<String>,
    pub netns: Option<String>,
    pub ifname: Option<String>,
    pub args: HashMap<String, String>,
    pub path: Vec<String>,
}

impl CniParams {
    pub fn from_env() -> Result<Self, CniError> {
        let command: Command = env::var("CNI_COMMAND")
            .map_err(|_| CniError::InvalidEnv("missing CNI_COMMAND".into()))?
            .parse()?;

        let container_id = env::var("CNI_CONTAINERID").ok();
        let netns = env::var("CNI_NETNS").ok();
        let ifname = env::var("CNI_IFNAME").ok();

        let args = env::var("CNI_ARGS")
            .unwrap_or_default()
            .split(';')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect();

        let path = env::var("CNI_PATH")
            .unwrap_or_default()
            .split(':')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();

        Ok(CniParams { command, container_id, netns, ifname, args, path })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_commands() {
        assert_eq!("ADD".parse::<Command>().unwrap(), Command::Add);
        assert_eq!("DEL".parse::<Command>().unwrap(), Command::Del);
        assert_eq!("CHECK".parse::<Command>().unwrap(), Command::Check);
        assert_eq!("VERSION".parse::<Command>().unwrap(), Command::Version);
        assert_eq!("GC".parse::<Command>().unwrap(), Command::Gc);
        assert_eq!("STATUS".parse::<Command>().unwrap(), Command::Status);
    }

    #[test]
    fn rejects_unknown_command() {
        assert!("FROBNICATE".parse::<Command>().is_err());
    }
}
