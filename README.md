This pusher library is a work-in-progress.  I would consider it an alpha
build at this point with not all necessary features added to make it a worthy
pusher library.  

Building
----------

    //First get the repository.
git clone https://<github username>@github.com/pusherClib
cd pusherClib

    // update the modules
git submodule init
git submoduel update

    // build the libwebsocket library
    // You can look in CMakeLists to see the various options.
mkdir libwebmodule/build
cd libwebmodule/build
    // build with shared libraries off depending on the target this will run on
cmake -DLWS_WITH_SHARED=OFF ..

    // Now build the pusher library
make

    // if you want to run the test program, set the values in config.h
    // properly with your Pusher api info then...
make test
./test


Contributions:

 - SGLIB, a simple library built on preprocessor for manipulating arrays, lists, trees, and containers.

 - libwebsocket library which is the basis of doing the Pusher integration

 - cJSON: A nice, simple JSON processor

