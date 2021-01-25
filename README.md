## README
[TODO]

This project is a fork of reflected-parameters project designed to be a stateful version.


# Build

To build via eclipse: Right Click on Project-> Run As-> Maven build

Or to build via console, execute the following command in project directory
```
$ mvn clean package
```

The Jar is created under the $project/target folder.
For more information about the build: [link](http://tutorials.jenkov.com/maven/maven-build-fat-jar.html)


# How does it work?

1. Analyze In Scope Http responses, registering the returned json values in memory (but, process only responses from Proxy).
2. Look for refections in the following In Scope HttpRequests
   * Here, we consider values in header and body.


You can use the following API for test purpose: https://repl.it/@Ailtonda/RESTserver#index.js
* Producer: https://restserver.ailtonda.repl.co/
* Consumer: https://restserver.ailtonda.repl.co/id123?id=id123
