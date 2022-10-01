#!/bin/sh

removeAlternatives() {
	update-alternatives --remove step /usr/bin/step-ca
}

upgrade() {
	:
}

remove() {
	removeAlternatives
}

action="$1"
if [ "$1" = "remove" ]; then
	action="remove"
elif [ "$1" = "upgrade" ] && [ -n "$2" ]; then
	action="upgrade"
elif [ "$1" = "disappear" ]; then
	action="remove"
fi

case "$action" in
	"0" | "remove")
		remove
		;;
	"1" | "upgrade")
		upgrade
		;;
	*)
		remove
		;;
esac
