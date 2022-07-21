local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")

local cjson = require("cjson")

OidcHandler.PRIORITY = 1050


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
  Temp = false
end

-- OidcHandler access methods will run when api is called
function OidcHandler:access(config)
  
  OidcHandler.super.access(self)

  -- require("resty.session").destroy(oidcConfig)
  local oidcConfig = utils.get_options(config, ngx)
  if config['client_id'] ~= Temp then
    Temp = config['client_id']
    ngx.req.clear_header('cookie')
    -- require("resty.session").destroy(oidcConfig)
  end

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end
  
  -- if true then
  --   return kong.response.exit(403, {
  --     config = config['client_id'],
  --     temp = temp,
  --     status = config['client_id'] ~= temp,
  --     header = ngx.req.get_headers()
  --   })
  -- end
  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  if oidcConfig.introspection_endpoint then
    response = introspect(oidcConfig)
    if response then
      utils.injectUser(response, oidcConfig['client_id'])
    end
  end

  -- utils.injectAccessToken and utils.injectUser are add headers parameter to the request
  if response == nil then
    response = make_oidc(oidcConfig)
    if response then
      if (response.user) then
        -- add user info (name, id, roles, etc) to request headers
        utils.injectUser(response.user)
        ngx.req.set_uri_args("filter")
        -- ngx.req.get_headers()['cookie']
        -- ngx.req.set_header('cookie', ngx.req.get_headers()['cookie'] .. '; ' .. 'access_token=' .. response.access_token)
        -- return kong.response.exit(403, {
        --   header = ngx.req.get_headers()['cookie'],
        --   type = type(ngx.req.get_headers()['cookie']),
        --   user = response.user,
        --   user_type = type(response.user),
        --   cast_table = cjson.encode(response.user),
        --   cast_table_type = type(cjson.encode(response.user)),
        -- })
      end
      if (response.access_token) then
    --     add access_token to request headers
        utils.injectAccessToken(response.access_token)
      end
    end
  end
end

-- function authenticate with oidc config 
-- this function return token and session
function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = require("resty.openidc").authenticate(oidcConfig)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end


function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end


return OidcHandler