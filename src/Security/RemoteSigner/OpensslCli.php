<?php

namespace Ekapusta\OAuth2Esia\Security\RemoteSigner;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\OpenSSL;

class OpensslCli extends OpenSSL
{
  private $toolPath;

  public function __construct($toolPath = 'openssl')
  {
    $this->toolPath = $toolPath;
  }

  public function getKeyType()
  {
    throw new \RuntimeException('not implemented');
  }

  public function getAlgorithm()
  {
    throw new \RuntimeException('not implemented');
  }

  public function getAlgorithmId()
  {
    return 'GOST3410_2012_256';
  }

  public function doVerify($expected, $payload, Key $key)
  {
    $publicKeyFile = tempnam(sys_get_temp_dir(), 'publicKeyFile');
    $messageFile = tempnam(sys_get_temp_dir(), 'messageFile');
    $signatureFile = tempnam(sys_get_temp_dir(), 'signatureFile');
    file_put_contents($publicKeyFile, $key->getContent());
    file_put_contents($messageFile, $payload);
    file_put_contents($signatureFile, $expected);

    $code = $this->runParameters([
      'dgst -engine gost -md_gost12_256',
      '-verify ' . escapeshellarg($publicKeyFile),
      '-signature ' . escapeshellarg($signatureFile),
      escapeshellarg($messageFile),
    ]);

    unlink($publicKeyFile);
    unlink($signatureFile);
    unlink($messageFile);

    return 0 == $code;
  }

  private function runParameters(array $parameters)
  {
    array_unshift($parameters, $this->toolPath);
    exec(implode(' ', $parameters), $output, $code);
    return $code;
  }
}