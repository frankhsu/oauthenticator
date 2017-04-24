"""
Okta Authenticator to use generic OAuth2 with JupyterHub

Derived from GenericOAuthenticator (@frankhsu)
"""

import base64
import json
import os

from traitlets import Dict, Unicode

from jupyterhub.auth import LocalAuthenticator
from tornado import gen, web
from tornado.auth import OAuth2Mixin
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.httputil import url_concat
from tornado.log import app_log as log

from .oauth2 import OAuthenticator, OAuthLoginHandler


class OktaEnvMixin(OAuth2Mixin):
    _OAUTH_ACCESS_TOKEN_URL = os.environ.get('OKTA_TOKEN_URL', '')
    _OAUTH_AUTHORIZE_URL = os.environ.get('OKTA_AUTHORIZE_URL', '')


class OktaLoginHandler(OAuthLoginHandler, OktaEnvMixin):
    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        self.log.info('oauth redirect: %r', redirect_uri)
        self.log.info('Getting code from authorization call')
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            response_type='code',
            scope=['email','openid'],
            extra_params={'state': 'requested',
                          'nonce': 'gusto'})
        self.log.info('Finished getting code from authorization call')


class OktaOAuthenticator(OAuthenticator):
    login_service = "Okta"
    login_handler = OktaLoginHandler
    log.info('Setting OAuth env vars')
    userdata_url = Unicode(
        os.environ.get('OKTA_USERDATA_URL', ''),
        config=True,
        help="Userdata url to get user data login information"
    )
    username_key = Unicode(
        os.environ.get('OKTA_USERNAME_KEY', 'email'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )

    authorize_url = Unicode(
        os.environ.get('OKTA_AUTHORIZE_URL', ''),
        config=True,
        help="Authorize url to get token"
    )
    token_url = Unicode(
        os.environ.get('OKTA_TOKEN_URL', ''),
        config=True,
        help="Token url to get token"
    )
    token_scopes = Unicode(
        os.environ.get('OKTA_TOKEN_SCOPES', ''),
        config=True,
        help="Scopes to get token"
    ).tag(config=True)

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()
        params = dict(
            grant_type='authorization_code',
            code=code,
            redirect_uri=self.get_callback_url(handler),
            scope='email openid',
        )

        url = url_concat(self.token_url, params)

        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
        )

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic " + "{}".format(b64key.decode("utf8"))
        }

        log.info('Getting access token from token call with authorization_code')
        log.info('URL: ' + url)
        req = HTTPRequest(url,
                          method='POST',
                          headers=headers,
                          body=''  # Body is required for a POST.
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format('Bearer', access_token)
        }
        url = url_concat(self.userdata_url, params)

        log.info('Getting verifying user with access_token')
        log.info('URL: ' + url)
        req = HTTPRequest(url,
                          method='GET',
                          headers=headers,
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if resp_json.get(self.username_key):
            return resp_json[self.username_key]


class LocalOktaOAuthenticator(LocalAuthenticator, OktaOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
