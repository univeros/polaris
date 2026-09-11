<?php

declare(strict_types=1);

namespace App\Http\Actions;

use Altair\Http\Base\Action;
use Altair\Http\Base\InputParser;
use App\Account\Me;
use App\Http\Responders\JsonResponder;

/**
 * Wires GET /app/me to its domain. The framework's `InputParser` hands the request attributes
 * (the authenticated token among them) to the domain as an `InputCollection`.
 */
final class MeAction extends Action
{
    public function __construct()
    {
        parent::__construct(domain: Me::class, responder: JsonResponder::class, input: InputParser::class);
    }
}
