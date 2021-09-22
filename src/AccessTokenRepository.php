<?php

namespace Brid\Auth;

class AccessTokenRepository
{

  /**
   * Revoke an access token.
   *
   * @param string $tokenId
   */
  public function revokeAccessToken(string $tokenId): void
  {
    //
  }

  /**
   * Check if the access token has been revoked.
   *
   * @param string $tokenId
   *
   * @return bool Return true if this token has been revoked
   */
  public function isAccessTokenRevoked(string $tokenId): bool
  {
    return false;
  }

}