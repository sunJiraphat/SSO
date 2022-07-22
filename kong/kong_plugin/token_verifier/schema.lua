return {
    no_consumer = true,
    fields = {
        Token_claim_name = { type = "string", required = true, default = "authorization" },
        Application_ID = { type = "string", required = true, default = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx" },
        iss_value = { type = "string", required = true, default = "Key******************" },
        iss = { type = "string", required = true, default = "iss" },
    }
}