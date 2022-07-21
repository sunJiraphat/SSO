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

    local httpc = http:new()
    local res, err = httpc:request_uri(plugin_conf.Application_Endpoint, { method = "GET" })
    if true then
        return kong.response.exit(403, {
            ep = plugin_conf.Application_Endpoint,
            -- header = ngx.req.get_headers()[plugin_conf.Token_claim_name]:gsub("Bearer ", ""),
            -- jwt = jwt_obj,
            data = res["keys"],
            err = err
          })
    end

    local whitelist = plugin_conf.whitelist
    local userroles = get_user_roles(plugin_conf.userinfo_header_name)

    if has_value(whitelist, userroles) then
        return
    else
        return kong.response.exit(403, {
            message = "Your role cannot consume this service",
            userroles = userroles,
            whitelist = whitelist,
            hesder = ngx.req.get_headers()
          })
        -- uncomment this for see why roles doesn't match
        -- return kong.response.exit(403, {
        --     whitelist = whitelist, userroles = userroles
        -- })
    end

end

function has_value (tab, val)
    for _, value in ipairs(tab) do
        for _, val_value in ipairs(val) do
            if value == val_value then
                return true
            end
        end
    end

    return false
end


function mysplit(inputstr, sep)
    if sep == nil then
        sep = "%s"
    end
    local t={} ;
    local i=1
    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
        t[i] = str
        i = i + 1
    end
    return t
end


function get_user_roles(userinfo_header_name)
    local h = ngx.req.get_headers()
    for k, v in pairs(h) do
        -- if header key == userinfo_header_name(default: X-Userinfo)
        if string.lower(k) == string.lower(userinfo_header_name) then
            local user_info = cjson.decode(ngx.decode_base64(v))
            -- user_info["roles"] is role like [admin, user, guest];
            local roles = table.concat(user_info["roles"],",")
            return mysplit(roles, ",")
        end
    end

    return {}
end


Token_verifier.PRIORITY = 1200


return Token_verifier