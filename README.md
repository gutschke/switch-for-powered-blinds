# switch-for-powered-blinds
Enables a Raspberry Pi (or clone) to raise/lower Hunter Douglas compatible blinds upon button presses

The program needs to be configured in the source file to find a Hunter
Douglas hub at a well-known URL. It also needs to be configured for a
well-known named room.

It then retrieves the current configuration from the hub and sorts the
different scenes by relative brightness. It has support for stacked
blinds (e.g. translucent & black-out). A two-position momentary
contact rocker switch (e.g. Leviton 5657-2) can be used to cycle
through these scenes.

As the hub occasionally returns incorrect data for scene descriptions, all
information is cached after having been retrieved the first time. The
cached contents should be reviewed and edited if errors are detected.

Relies on the "wiring" library to read the position of the rocker switch,
and requires a modified JSMN library to parse JSON (https://github.com/gutschke/jsmn)
