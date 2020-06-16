sudo chown -R root:wheel build/Release/vuln.kext
sudo kextutil build/Release/vuln.kext
sudo chown -R `id -un`:`id -gn` build/Release/vuln.kext
