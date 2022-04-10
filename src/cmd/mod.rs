pub mod add;
pub mod delete;
pub mod generate;
pub mod get;
pub mod list;
pub mod validate;

pub enum CommandType {
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
            CommandType::Generate => "generate",
            CommandType::Add => "add",
            CommandType::Delete => "delete",
            CommandType::List => "list",
            CommandType::Get => "get",
            CommandType::Validate => "validate",
        }
    }
}
