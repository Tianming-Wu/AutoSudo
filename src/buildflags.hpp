/*
    What this build lets through, in one place.

    A debug build is the one a non-elevated GUI is pointed at while it is being written, so
    it relaxes the rule side: the control channel is created for everyone, a caller that is
    not elevated is accepted, and the key of the rule database is left with the default
    descriptor of the process rather than being locked to SYSTEM and Administrators. All
    three follow from the one constant below, and none of them holds in a release build.

    A debug service says so out loud when it starts. It is not meant to be installed.
*/

#pragma once

// Whether rule operations are accepted from a caller that is not elevated.
#ifdef _DEBUG
inline constexpr bool allowUnelevatedRuleCallers = true;
#else
inline constexpr bool allowUnelevatedRuleCallers = false;
#endif
