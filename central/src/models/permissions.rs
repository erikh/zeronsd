/*
 * ZeroTier Central API
 *
 * ZeroTier Central Network Management Portal API.<p>All API requests must have an API token header specified in the <code>Authorization: Bearer xxxxx</code> format.  You can generate your API key by logging into <a href=\"https://my.zerotier.com\">ZeroTier Central</a> and creating a token on the Account page.</p><p>eg. <code>curl -X GET -H \"Authorization: bearer xxxxx\" https://my.zerotier.com/api/network</code></p>
 *
 * The version of the OpenAPI document: v1
 * 
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Permissions {
    /// Authorize permission
    #[serde(rename = "a", skip_serializing_if = "Option::is_none")]
    pub a: Option<bool>,
    /// Delete permission
    #[serde(rename = "d", skip_serializing_if = "Option::is_none")]
    pub d: Option<bool>,
    /// Modify network settings permission
    #[serde(rename = "m", skip_serializing_if = "Option::is_none")]
    pub m: Option<bool>,
    /// Read network settings permission
    #[serde(rename = "r", skip_serializing_if = "Option::is_none")]
    pub r: Option<bool>,
}

impl Permissions {
    pub fn new() -> Permissions {
        Permissions {
            a: None,
            d: None,
            m: None,
            r: None,
        }
    }
}


