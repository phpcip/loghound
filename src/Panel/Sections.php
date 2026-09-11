<?php
/**
 * Loghound — a view that declares its own cards.
 *
 * ONE ORDERED LIST, THREE CONSUMERS. A view that implements this returns the cards it is
 * about to render, in render order, and that single list drives:
 *
 *   1. the sticky jump bar Layout pins above the page (Layout::sectionNav());
 *   2. the number printed on each card (Layout::cardNum());
 *   3. the order the view's own body() walks, where the view chooses to.
 *
 * It exists because those three used to be maintained separately and drifted: on Settings,
 * two cards claimed 02 and two claimed 03, and the jump bar had to be kept in step with
 * eleven `cardOpen()` call sites by hand. A number that is a literal at the call site is a
 * number that is wrong as soon as a card is inserted above it.
 *
 * WHY AN INTERFACE RATHER THAN A METHOD ON Controller. The nav has to be emitted OUTSIDE
 * `.view` — a `position: sticky` child of a flex column is sticky within its own item box,
 * which is exactly as tall as its content, so it has no travel and scrolls away. That means
 * Layout needs the list BEFORE it calls body(), and asking for it through an interface lets
 * a view opt in without every Controller subclass being obliged to have an opinion.
 *
 * @package Loghound
 * @license MIT
 */

declare(strict_types=1);

namespace Loghound\Panel;

interface Sections
{
    /**
     * The cards this view renders, in the order it renders them.
     *
     * Each entry is `[card id, short nav label]` and may carry further elements the view
     * uses for its own dispatch; Layout reads only the first two. The card id is the base
     * id handed to Controller::cardOpen(), NOT the `-card` suffixed element id.
     *
     * The label is the one shown in the jump bar, so it is deliberately shorter than the
     * card's heading: the bar is one row that never wraps, and eleven full headings do not
     * fit on one at any realistic width.
     *
     * @return array<int,array<int,string>>
     */
    public function sections(): array;
}
