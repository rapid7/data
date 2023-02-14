# Codesys deobfuscator scripts

These scripts can be used to deobfuscate encrypted Codesys binaries.

The binaries, delivered by CODESYS GmbH when you download a distribution for a
Raspberry Pi, Beaglebone Black etc. from their website, are obfuscated.

The ELF files decrypt themselves using a small loader stub and then jump to the
original entrypoint. These scripts do the same and apply some patches to remove
the deobfuscation afterwards and disable some anti-debug measures. For more
information how to use them, check the comments at the top of the two files
