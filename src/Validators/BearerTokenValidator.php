<?php

namespace Brid\Auth\Validators;

use Brid\Auth\Exceptions\OAuthServerException;
use DateTimeZone;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\ValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Http\Message\ServerRequestInterface;

class BearerTokenValidator
{

  /**
   * @var mixed
   */
  private $accessTokenRepository;

  /**
   * @var string
   */
  protected string $publicKey;

  /**
   * @var Configuration
   */
  private Configuration $jwtConfiguration;

  /**
   * @param $accessTokenRepository
   */
  public function __construct($accessTokenRepository)
  {
    $this->accessTokenRepository = $accessTokenRepository;
  }

  /**
   * Set the public key
   *
   * @param string $path
   * @return BearerTokenValidator
   */
  public function setPublicKey(string $path): static
  {
    $this->publicKey = storage_path($path);

    $this->initJwtConfiguration();

    return $this;
  }

  /**
   * Initialise the JWT configuration.
   */
  private function initJwtConfiguration()
  {
    $this->jwtConfiguration = Configuration::forSymmetricSigner(
      new Sha256(),
      InMemory::plainText('')
    );

    $this->jwtConfiguration->setValidationConstraints(
      new ValidAt(new SystemClock(new DateTimeZone(\date_default_timezone_get()))),
      new SignedWith(new Sha256(), LocalFileReference::file($this->publicKey))
    );
  }

  /**
   * @param ServerRequestInterface $request
   * @return ServerRequestInterface
   * @throws OAuthServerException
   */
  public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
  {
    if ($request->hasHeader('authorization') === false) {
      throw OAuthServerException::accessDenied('Missing "Authorization" header');
    }

    $header = $request->getHeader('authorization');
    $jwt = \trim((string) \preg_replace('/^(?:\s+)?Bearer\s/', '', $header[0]));

    try {
      // Attempt to parse and validate the JWT
      $token = $this->jwtConfiguration->parser()->parse($jwt);

      $constraints = $this->jwtConfiguration->validationConstraints();

      try {
        $this->jwtConfiguration->validator()->assert($token, ...$constraints);
      } catch (RequiredConstraintsViolated $exception) {
        throw OAuthServerException::accessDenied('Access token could not be verified');
      }
    } catch (CannotDecodeContent | InvalidTokenStructure | UnsupportedHeaderFound $exception) {
      throw OAuthServerException::accessDenied($exception->getMessage(), null, $exception);
    }

    $claims = $token->claims();

    // Check if token has been revoked
    if ($this->accessTokenRepository->isAccessTokenRevoked($claims->get('jti'))) {
      throw OAuthServerException::accessDenied('Access token has been revoked');
    }

    // Return the request with additional attributes
    return $request
      ->withAttribute('oauth_access_token_id', $claims->get('jti'))
      ->withAttribute('oauth_client_id', $this->convertSingleRecordAudToString($claims->get('aud')))
      ->withAttribute('oauth_user_id', $claims->get('sub'))
      ->withAttribute('oauth_scopes', $claims->get('scopes'));
  }

  /**
   * Convert single record arrays into strings to ensure backwards compatibility between v4 and v3.x of lcobucci/jwt
   *
   * @param mixed $aud
   *
   * @return array|string
   */
  private function convertSingleRecordAudToString(mixed $aud): array|string
  {
    return \is_array($aud) && \count($aud) === 1 ? $aud[0] : $aud;
  }
}
