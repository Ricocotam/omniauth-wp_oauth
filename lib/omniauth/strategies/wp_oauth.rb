require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class WP_OAuth < OmniAuth::Strategies::OAuth2

      # Give your strategy a name.
      option :name, :wp_oauth

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        :response_type => "code"
      }

      # You may specify that your strategy should use PKCE by setting
      # the pkce option to true: https://tools.ietf.org/html/rfc7636
      option :pkce, true

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid do
        raw_info['ID']
      end

      info do
        {
          :email => raw_info['email'],
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      #def callback_url
      #  full_host + callback_path
      #end


      def raw_info
        @raw_info ||= access_token.get('/me').parsed
        @raw_info
      end

    end
  end
end
