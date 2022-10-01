#!/bin/sh

updateAlternatives() {
	update-alternatives --install /usr/bin/step-ca step-ca /usr/bin/step-ca 50
}

cleanInstall() {
	updateAlternatives
	updateCompletion
}

upgrade() {
	updateAlternatives
	updateCompletion
}

action="$1"
if [ "$1" = "configure" ] && [ -z "$2" ]; then
	action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
	action="upgrade"
fi

case "$action" in
	"1" | "install")
		cleanInstall
		;;
	"2" | "upgrade")
		upgrade
		;;
	*)
		cleanInstall
		;;
esac
