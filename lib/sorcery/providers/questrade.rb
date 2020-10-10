module Sorcery
  module Providers
    class Questrade < Base
      include Protocols::Oauth2

      attr_accessor :auth_site, :auth_path, :scope, :token_path, :user_info_path, :token, :api_url

      def initialize
        super

        @api_url = nil
        @token = nil
        @scope = 'read_acc read_md'
        @site = 'https://login.questrade.com/'
        @auth_path = '/oauth2/authorize'
        @token_path = "/oauth2/token"
        @user_info_path = "/v1/accounts"
        @state = SecureRandom.hex(16)
      end

      def get_user_hash(access_token)
        begin
          @token.client.site = @api_url

          response = access_token.get(user_info_path)

          body = JSON.parse(response.body)
          auth_hash(access_token).tap do |h|
            h[:user_info] = body
            h[:uid] = body['userId']
          end
        ensure
          @token.client.site = @site
        end
      end

      def login_url(_params, _session)
        authorize_url(authorize_url: auth_path)
      end

      def process_callback(_params, _session)
        args = {}.tap do |a|
          a[:code] = _params[:code] if _params[:code]
        end

        args = args
        options = {
          token_url: token_path,
          client_id: @key,
          grant_type: 'authorization_code',
          token_method: :post,
        }
        @token = get_access_token(args, options)
        @api_url = token.params['api_server']

        token
      end
    end
  end
end