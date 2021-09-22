<?php

namespace Brid\Auth;

use AsyncAws\Ssm\Input\GetParametersRequest;
use AsyncAws\Ssm\SsmClient;
use Brid\Core\Foundation\Providers\ServiceProvider;
use Exception;

class SSMOAuthServiceProvider extends ServiceProvider
{

  protected SsmClient $ssm;

  public function __construct()
  {
    if (!defined('APP_HANDLER_TYPE') || APP_HANDLER_TYPE !== 'http') {
      return;
    }

    $this->ssm = new SsmClient($this->getConfig());
  }

  private function getConfig(): array
  {
    $config = config('aws');

    return [
      'accessKeyId' => $config['credentials']['key'],
      'accessKeySecret' => $config['credentials']['secret'],
      'region' => $config['region'],
    ];
  }

  /**
   * @throws Exception
   */
  public function boot()
  {
    if (!defined('APP_HANDLER_TYPE') || APP_HANDLER_TYPE !== 'http') {
      return;
    }

    $privateKeyPath = storage_path('/oauth-private.key');
    $publicKeyPath = storage_path('/oauth-public.key');

    if (is_readable($privateKeyPath) && is_readable($publicKeyPath)) {
      return;
    }

    $keys = $this->getKeys();

    if (blank($keys['private']) || blank($keys['public'])) {
      throw new Exception('Passport keys not set on AWS SSM.');
    }

    $this->saveKeys($keys['private'], $keys['public']);

  }

  /**
   * @return array
   */
  private function getKeys(): array
  {

    $keys = [
      'private' => config('auth.jwt.ssm.private'),
      'public' => config('auth.jwt.ssm.public'),
    ];

    $parameters = $this->ssm->getParameters(new GetParametersRequest([
      'Names' => array_values($keys),
      'WithDecryption' => true,
    ]))->getParameters();

    foreach ($parameters as $parameter)
    {
      if ($keys['private'] === $parameter->getName()) {
        $keys['private'] = $parameter->getValue();
        continue;
      }

      $keys['public'] = $parameter->getValue();
    }

    return $keys;

  }

  /**
   * @param string $privateKey
   * @param string $publicKey
   */
  private function saveKeys(string $privateKey, string $publicKey): void
  {
    $privateKeyPath = storage_path('/oauth-private.key');
    $publicKeyPath = storage_path('/oauth-public.key');

    file_put_contents($privateKeyPath, $privateKey);
    file_put_contents($publicKeyPath, $publicKey);
    chmod($privateKeyPath, 0660);
    chmod($publicKeyPath, 0660);
  }

}