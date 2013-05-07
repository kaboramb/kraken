pluginsdir = $(datarootdir)/@PACKAGE@/plugins
plugins_DATA = plugins/*

desktopdir = $(datadir)/applications
desktop_DATA = kraken.desktop
UPDATE_DESKTOP = update-desktop-database $(datadir)/applications || :

install-data-hook:
	$(UPDATE_DESKTOP)
uninstall-hook:
	$(UPDATE_DESKTOP)
