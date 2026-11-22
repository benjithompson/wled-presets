# Domain glossary

The words the code and its reviews use for this project. Add a term when a module is named after it.

- **Yard**: the house and garden with lights on it, as the layout describes them.
- **Fixture** (an *object* in the editor): one thing in the layout with LEDs on it: the roof, a line, a bush, a tree, a semicircle or a custom object. Its *kind* says which.
- **Stage**: the layout turned into LED positions, ready for effects and games to draw on ([shared/layout.ts](shared/layout.ts) `buildStage`).
- **Line**: the queue visitors join to use the lights. Whoever's turn it is holds the lights ([server/src/line.ts](server/src/line.ts)).
- **Game**: something one or two visitors play on the lights from their phone. The catalog lists them ([shared/games.ts](shared/games.ts)), and the game host runs one at a time ([server/src/game/host.ts](server/src/game/host.ts)).
- **Round**: what every game shares around its own rules: its phase and how long it has been in it, starting again after the end, its scoreboard, and the status when the layout has nowhere to play it ([server/src/game/round.ts](server/src/game/round.ts)). Phases the host goes by: `ready` (waiting, with the scoreboard) and `over` or `won` (ended).
- **Show**: the light show the whole yard puts on around a game: a mood, pulses, fireworks, sweeps ([server/src/game/show.ts](server/src/game/show.ts)). A game draws it with its other effects through `Fx`.
- **Scoreboard** (a *board*): the top scores for one game, or for one level of a game, with three-letter initials.
- **Tones**: the colors games play with (orbs, beads, buttons, layers), far apart on real LEDs and none of the colors that mean something else: white, gold (points) and red (a mistake) ([server/src/game/kit.ts](server/src/game/kit.ts) `TONES`, next to `COLORS`). Colors themselves, and the small maths around them, are in [shared/color.ts](shared/color.ts).
- **Switched off**: a device an admin turned off here. Off holds: scenes, colors and games leave it dark, and only an editor's preview wakes it while the admin looks. `takesFrames` ([server/src/lightSender.ts](server/src/lightSender.ts)) is the one rule for which devices get frames; the switches themselves are in `Lights`.
- **Transition**: how one show of the lights gives way to the next: a crossfade, a wipe, a flash and more, or "random" (a different one each time) ([shared/transitions.ts](shared/transitions.ts)). Clips in a sequence come in and go out with one; scenes someone picks change with the one in the settings (the auto-revert changes at once).
