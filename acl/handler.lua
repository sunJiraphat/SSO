local ACL = require("kong.plugins.base_plugin"):extend()
local cjson = require("cjson")

function ACL:new()
    ACL.super.new(self, "oidc-acl")
end


function ACL:access(plugin_conf)
    ACL.super.access(self)

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


ACL.PRIORITY = 950


return ACL