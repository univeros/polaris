<?php

declare(strict_types=1);

namespace Univeros\Polaris\Security;

use Override;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Log\LoggerInterface;
use SensitiveParameter;
use Throwable;
use Univeros\Polaris\Contracts\BreachedPasswordCheckInterface;

use function explode;
use function sha1;
use function strtoupper;
use function strtr;
use function substr;

/**
 * Have I Been Pwned adapter using the k-anonymity range API: only the first five characters of
 * the password's SHA-1 ever leave the process; the response lists suffixes for that prefix and
 * the comparison happens locally. The host supplies the PSR-18 client + PSR-17 request factory.
 *
 * Fail-open by contract: a network error, a non-200, or any parsing surprise logs a warning and
 * reports "not breached" — a third-party outage must not block sign-ups or password changes.
 */
final class HibpBreachedPasswordCheck implements BreachedPasswordCheckInterface
{
    private const string ENDPOINT = 'https://api.pwnedpasswords.com/range/';

    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requests,
        private readonly LoggerInterface $logger,
    ) {
    }

    #[Override]
    public function isBreached(#[SensitiveParameter] string $password): bool
    {
        $hash = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        try {
            $request = $this->requests->createRequest('GET', self::ENDPOINT . $prefix)
                ->withHeader('Add-Padding', 'true');
            $response = $this->client->sendRequest($request);

            if ($response->getStatusCode() !== 200) {
                $this->logger->warning('HIBP range query returned {status}; treating as not breached.', [
                    'status' => $response->getStatusCode(),
                ]);

                return false;
            }

            foreach (explode("\n", (string) $response->getBody()) as $line) {
                $parts = explode(':', strtr($line, ["\r" => '']), 2);
                // Padding rows and dataset removals carry a count of 0 and read as clean.
                if ($parts[0] === $suffix && (int) ($parts[1] ?? '0') > 0) {
                    return true;
                }
            }

            return false;
        } catch (Throwable $exception) {
            $this->logger->warning('HIBP range query failed: {reason}; treating as not breached.', [
                'reason' => $exception->getMessage(),
                'exception' => $exception,
            ]);

            return false;
        }
    }
}
