<?php
/**
 * Loghound — the contract a panel view must satisfy to accept POSTs.
 *
 * The front controller used to name one concrete class, so state-changing requests could
 * only ever reach Settings and any other view that grew an asynchronous operation was
 * silently unreachable: the button would post, the router would answer 405, and the only
 * clue would be in the browser console. Routing on a capability instead of on an identity
 * removes that whole class of dead end.
 *
 * Implementing this is a deliberate act. A view that does not implement it cannot be
 * POSTed to at all, which keeps the default fail-closed: read-only views stay read-only
 * without having to remember to say so.
 *
 * The implementer is responsible for the checks the front controller does not do for it —
 * authentication, the CSRF token, and validating every field it reads out of the body.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

interface JobHost
{
    /**
     * Handle one POST and return the URL the browser should be redirected to.
     *
     * Returning a target rather than emitting the response keeps POST/Redirect/GET in one
     * place in the front controller. A handler answering with JSON — as the job endpoints
     * do — exits instead of returning, because there is nothing to redirect to.
     *
     * @throws \Throwable The front controller logs the detail and shows the operator a
     *                    generic failure, so a message here may name internals.
     */
    public function post(): string;
}
