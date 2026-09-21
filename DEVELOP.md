# Development Notices and Plans

## Notices

Some Rule apis are not tested, like deleting rules, and creating rules with an recycled id.
It is simply because AutoSudoGUI is not completed yet. Currently, it is not possible to delete a single rule without wiping the entire rule database. However, there was an reserved "bypass" action that can disable a rule. It will still be evaluated so it still causes performance impact, but who cares. We won't have that many rules until the system is complete, when deleting rules is implemented.

## Plans

Downgrade some log outputs in the rule api (AutoSudoSdk) from info to debug. For example, listing rules request and listing rules result. The GUI is constantly requesting these data, and it will fill the log with these if they are info logs.

Show a log to indicate that the rule is approved, it looked a bit weird if nothing was logged. It is currently a problem because there weren't any logging inside the RuleEngine (and it is intentional).

Modify the "Receive command" log to be a little more informative. I might need to spend some time to figure out how to log the request details without putting too much information in the log. There need to be a way to keep track of the requests sent to AutoSudo anyway.

Well, here's an idea: We add a new log channel (approval_history.log) and log requests there. Inside the main log we only record the executable and approval result. This should solve the problem, but probably requires some tweaks on logt before that's practicle.


There are still sometimes problems about AutoSudoBroker not exiting. Probably some problems with terminate signal handling. I will need to spend some time to figure out the problem and fix it, and before that I need to consistently reproduce the problem.