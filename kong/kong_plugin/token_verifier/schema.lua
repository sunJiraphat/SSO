return {
    no_consumer = true,
    fields = {
        Token_claim_name = { type = "string", required = true, default = "authorization" },
        Application_Endpoint = { type = "string", required = true, default = "https://login.microsoftonline.com/{Directory (tenant) ID}/v2.0/.well-known/openid-configuration" },
        Application_ID = { type = "string", required = true, default = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx" },
        Application_Secret = { type = "string", required = true, default = "Key******************" },
        Application_Secret_Expires = { type = "string", required = true, default = "1/1/2099" },
    }
}