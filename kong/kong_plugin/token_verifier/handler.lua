local Token_verifier = require("kong.plugins.base_plugin"):extend()
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

    if os.time() > jwt_obj['payload']['exp'] then
        return kong.response.exit(401, {
            code = 401002,
            message = "JWT Token expired"
          })
    end

    if jwt_obj['payload']['appid'] ~= plugin_conf.Application_ID then
        return kong.response.exit(401, {
            code = 401001,
            message = "Application_ID doesn't match"
            })
    end

    if jwt_obj['payload'][plugin_conf.iss] == nil then
        return kong.response.exit(401, {
            code = 401001,
            message = "JWT Token iss missing"
            })
    else
        if jwt_obj['payload'][plugin_conf.iss] ~= plugin_conf.iss_value then
            return kong.response.exit(401, {
                code = 401001,
                message = "JWT Token iss invalid"
              })
        end
    end

    -- if true then
    --     return kong.response.exit(403, {
    --         ep = jwt_obj,
    --         iss = plugin_conf.iss,
    --         iss_value = plugin_conf.iss_value,
    --         -- header = ngx.req.get_headers()[plugin_conf.Token_claim_name]:gsub("Bearer ", ""),
    --       })
    -- end
    return
end


Token_verifier.PRIORITY = 1200


return Token_verifier