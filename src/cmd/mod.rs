pub mod add;
pub mod delete;
pub mod generate;
pub mod get;
pub mod init;
pub mod list;
pub mod validate;

pub enum CommandType {
    Init,
    Generate,
    Add,
    Delete,
    List,
    Get,
    Validate,
}

impl CommandType {
    pub fn as_str(&self) -> &str {
        match self {
            CommandType::Init => "init",
            CommandType::Generate => "generate",
            CommandType::Add => "add",
            CommandType::Delete => "delete",
            CommandType::List => "list",
            CommandType::Get => "get",
            CommandType::Validate => "validate",
        }
    }
}
