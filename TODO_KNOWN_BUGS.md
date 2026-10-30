# TODO and KNOWN BUGS 

A list of stuff to do and known bugs.

## Known bugs

1. Keybinding `ctrl+X` will ask for sudo permissions but will fail to render the program correctly and permissions will not be inherited correctly. Needs fixing
2. On Home tab in list with Fixes, when applying a fix it adds another rule instead of replacing the one it is supposed to fix.
3. Clearing the view on `Activity` tab does not work.

## TODO List

A list of future fixes that needs working on.

1. When editing a rule, automatically open it in the last step "advanced" of the wizard.
2. Create a settings tab with configurable settings for:
2.1Editing default settings for new rules(Action, Direction, Interface, Protocol, From adress, To Address, Logging)
2.2 Checkbox for only using advanced and Review steps when creating new rules (Skip wizard)
2.3 Keybinding `E`(advanced edit) on a rule should display an edit box for editing only the actual line sent to ufw. 
2.4 Example: "ufw limit in log-all proto tcp from 192.168.1.1 to any port 22 comment 'ufw-manager-tui: blocked from activity'". 