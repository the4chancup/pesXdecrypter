About
-----

This is a working decrypter and encrypter for EDIT files (also known as save game) generated by Pro Evolution Soccer 2016/2016 myClub edition/2017.

Compiled binaries for Windows are available [here on Github](https://github.com/the4chancup/pesXdecrypter/releases).

This project was initially developed as 'pes16decrypter' by a contributer who now wishes to remain anonymous. May he rest well among the fish.

Since then, support for new PES versions and CMake has been added.

Background
----------

All save files generated by the games mentioned above are encrypted using an interesting combination of Mersenne Twister and some kind of chained encryption key.

Each file consists of six different blocks that are encrypted differently. In the order they appear in the file, they are

* The encryption header. This contains part of the information required to decrypt the file. This is seeded differently every time PES16 saves a file.
* The file header. This specifies the type of file (EDIT, TEXPORT, SYSTEM etc.), the length of the remaining blocks in the file and some sort of hash/checksum (the game does not seem to care about this).
* A thumbnail/logo. You would think this would be displayed when selecting the save state to load, but the game seems to ignore this.
* The file description. This contains one or two strings about what is in the file, such as the name of the team. This is mainly for aesthetics, i.e. displaying the correct name when listing save states.
* The actual save game data. This contains the team data/system settings/other things. This is probably the main thing you want to edit.
* A serial number/version string. We don't know what this is for, but you probably shouldn't change this.

Usage
-----

This project comes with two command line tools and a DLL that do decryption and encryption, respectively.

To decrypt a file, run (replace XXX with the version of PES you are using)

	decrypterXXX input_file output_directory

This will decrypt the file at `input_file`, split it up into different data blocks and save the resulting files into `output_directory`.

You can edit the decrypted files directly. After you're done, run the encrypter with

	encrypterXXX input_directory output_file

This will encrypt the different files from the specified output directory and merge them into a single output file that can be read by PES16.

A DLL is provided for when you want to use the decrypter/encrypter in an external program. Please see `src/encrypter.c` and `src/decrypter.c` for examples on how to use the library functions.

Compilation
-----------

This project is written in C; build files (such as for make) can be generated using CMake.

Make sure you have CMake and a compiler of your choice installed (we recommend MinGW for Windows).

You have to add the bin directory of both MingGW and CMake to the system Path variable for everything to work.

Run CMake (cmake-gui), create a build folder within the project folder, and from this build folder run configure and generate a MinGW Makefile.

Then, from within the same folder, run the following from command line:

	mingw32-make

A bunch of libraries and executables should now be built.

If you are using Linux/Unix, you should be able to compile the project just fine as well.


License
-------

This project is released into the public domain. You are allowed to modify, redistribute and sell the code without need for attribution. Please consider contributing back to the community and releasing your code if you build on top of this project.

Please note that this license does not apply to `src/mt19937ar.c`, which was made available by Takuji Nishimura and Makoto Matsumoto. Please respect their license when redistributing the code or binaries.