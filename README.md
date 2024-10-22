# UFmyMusic App

This is an app that allows users to synchronize their files with a centralized server.

## How to run

Git clone the repo. From there, add whatever txt files you want to the server and to the client.
Run **make all** to create the executables.
run **./resolver** to start the server
run **./requester** to connect a client. You can open a new terminal to simulate multiple client connections.

The supported messages are LIST, DIFF, PULL, and LEAVE.

* LIST will list all the files the server currently has
* DIFF will list all the files that the client does not have
* PULL will send all the files that the client does not have
* LEAVE will disconnect the client from the server

## Implementation Details

This is setup to only be able to interact with whatever is in the ./server/ and ./client/ directories.

A surplus of files that the client could send has no effect on the DIFF or PULL service. The server simply just checks if the client does **not** have what the server currently contains.

The server determines this by first checking the filename. If they are the same, it will then compare the hash of the file contents.
