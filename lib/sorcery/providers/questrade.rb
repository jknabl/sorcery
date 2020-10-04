module Sorcery
  module Providers
    class Questrade < Base
      include Protocols::Oauth2

      attr_accessor :auth_site, :auth_path, :scope, :token_path, :user_info_path

      def initialize
        super

        @scope = 'read_acc read_md'
        @site = 'https://login.questrade.com/'
        @auth_path = '/oauth2/authorize'
        @token_path = "/oauth2/token"
        @user_info_path = "/accounts"
        @state = SecureRandom.hex(16)
      end

      def get_user_hash(access_token)
        response = access_token.get(user_info_path, params: { token: access_token.token })
        body = JSON.parse(response.body)
        auth_hash(access_token).tap do |h|
          h[:user_info] = body
          h[:uid] = body['id']
        end
      end

      def login_url(_params, _session)
        authorize_url(authorize_url: auth_path)
      end

      def process_callback(_params, _session)
        args = {}.tap do |a|
          a[:code] = _params[:code] if _params[:code]
        end
        get_access_token(
          args,
          token_url: token_path,
          client_id: @key,
          grant_type: 'authorization_code',
          token_method: :post
        )
      end
    end
  end
end