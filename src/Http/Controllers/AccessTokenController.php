<?php

namespace Kayrules\LumenPassport\Http\Controllers;

use MoeenBasra\LaravelPassportMongoDB\Passport;
use MoeenBasra\LaravelPassportMongoDB\Token;
use Zend\Diactoros\Response as Psr7Response;
use Psr\Http\Message\ServerRequestInterface;
use Kayrules\LumenPassport\LumenPassport;

/**
 * Class AccessTokenController
 * @package Kayrules\LumenPassport\Http\Controllers
 */
class AccessTokenController extends \MoeenBasra\LaravelPassportMongoDB\Http\Controllers\AccessTokenController
{
    /**
     * Authorize a client to access the user's account.
     *
     * @param  ServerRequestInterface  $request
     * @return Response
     */
    public function issueToken(ServerRequestInterface $request)
    {
        $response = $this->withErrorHandling(function () use ($request) {
            $input = (array) $request->getParsedBody();
            $clientId = isset($input['client_id']) ?? null;

            // Overwrite password grant at the last minute to add support for customized TTLs
            $this->server->enableGrantType(
                $this->makePasswordGrant(), LumenPassport::tokensExpireIn(null, $clientId)
            );

            return $this->server->respondToAccessTokenRequest($request, new Psr7Response);
        });

        if ($response->getStatusCode() < 200 || $response->getStatusCode() > 299) {
            return $response;
        }

        $payload = json_decode($response->getBody()->__toString(), true);

        if (isset($payload['access_token'])) {
            $tokenId = $this->jwt->parse($payload['access_token'])->getClaim('jti');
            $token = $this->tokens->find($tokenId);

            if (!($token->client->firstParty() && LumenPassport::$allowMultipleTokens)) {
                $this->revokeOrDeleteAccessTokens($token, $tokenId);
            }
        }

        return $response;
    }

    /**
     * Create and configure a Password grant instance.
     *
     * @return \League\OAuth2\Server\Grant\PasswordGrant
     */
    private function makePasswordGrant()
    {
        $grant = new \League\OAuth2\Server\Grant\PasswordGrant(
            app()->make(\MoeenBasra\LaravelPassportMongoDB\Bridge\UserRepository::class),
            app()->make(\MoeenBasra\LaravelPassportMongoDB\Bridge\RefreshTokenRepository::class)
        );

        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

        return $grant;
    }

    /**
     * Revoke the user's other access tokens for the client.
     *
     * @param  Token $token
     * @param  string $tokenId
     * @return void
     */
    protected function revokeOrDeleteAccessTokens(Token $token, $tokenId)
    {
        $query = Token::where('user_id', $token->user_id)->where('client_id', $token->client_id);

        if ($tokenId) {
            $query->where('id', '<>', $tokenId);
        }

        if (Passport::$pruneRevokedTokens) {
            $query->delete();
        } else {
            $query->update(['revoked' => true]);
        }
        if($query) {

        }
    }
}
