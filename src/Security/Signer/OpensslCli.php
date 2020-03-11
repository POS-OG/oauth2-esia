<?php

namespace Ekapusta\OAuth2Esia\Security\Signer;

use Ekapusta\OAuth2Esia\Security\Signer;
use Ekapusta\OAuth2Esia\Security\Signer\Exception\SignException;

class OpensslCli extends Signer
{
    private $toolPath;

    public function __construct(
        $certificatePath,
        $privateKeyPath,
        $privateKeyPassword = null,
        $toolPath = 'sudo cryptcp'
    ) {
        parent::__construct($certificatePath, $privateKeyPath, $privateKeyPassword);
        $this->toolPath = $toolPath;
    }

    public function sign($message)
    {

        $messageFile = tempnam(sys_get_temp_dir(), 'messageFile');
        $signFile = tempnam(sys_get_temp_dir(), 'signFile');
        file_put_contents($messageFile, $message);

        return $this->runParameters([
            '-sign -pin '. escapeshellarg($this->privateKeyPassword).' '. $messageFile . ' ' . $messageFile.'.sig',
        ], $messageFile . '.sig');
    }

    private function runParameters(array $parameters, $input)
    {
        array_unshift($parameters, $this->toolPath);

        return $this->run(implode(' ', $parameters), $input);
    }

    /**
     * Runs command with input from STDIN.
     */
    private function run($command, $input)
    {
        $process = proc_open($command, [
            ['pipe', 'r'], // stdin
            ['pipe', 'w'], // stdout
            ['pipe', 'w'], // stderr
        ], $pipes);

        fwrite($pipes[0], '');
        fclose($pipes[0]);

        $result = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        $code = proc_close($process);

        if (0 != $code) {
            $errors = trim($errors) ?: 'unknown';
            throw SignException::signFailedAsOf($errors, $code);
        }

        $signed = base64_decode(file_get_contents($input));
        return $signed;
    }
}
