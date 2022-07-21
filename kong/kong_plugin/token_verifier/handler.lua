local Token_verifier = require("kong.plugins.base_plugin"):extend()
local cjson = require("cjson")
local http = require("resty.http")
local jwt = require("resty.jwt")

function Token_verifier:new()
    Token_verifier.super.new(self, "token-verifier")
end


function Token_verifier:access(plugin_conf)
    Token_verifier.super.access(self)
    
    if ngx.req.get_headers()[plugin_conf.Token_claim_name] == nil then
        return kong.response.exit(401, {
            code = 401001,
            message = "JWT Token missing in request headers"
          })
    end

    local jwt_obj = jwt:load_jwt(ngx.req.get_headers()[plugin_conf.Token_claim_name]:gsub("Bearer ", ""))

    if jwt_obj['valid'] == false then
        return kong.response.exit(401, {
            code = 401001,
            message = "JWT Token invalid"
          })
    end

    if os.time() > jwt_obj['payload']['exp'] and false then
        return kong.response.exit(401, {
            code = 401002,
            message = "JWT Token expired"
          })
    end

    -- local httpc = http:new()
    -- local res, err = httpc:request_uri(plugin_conf.Application_Endpoint, { method = "GET" })
    -- if true then
    --     return kong.response.exit(403, {
    --         ep = plugin_conf.Application_Endpoint,
    --         -- header = ngx.req.get_headers()[plugin_conf.Token_claim_name]:gsub("Bearer ", ""),
    --         -- jwt = jwt_obj,
    --         data = res["keys"],
    --         err = err
    --       })
    -- end
    return
end


Token_verifier.PRIORITY = 1200


return Token_verifier