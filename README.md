## README
[TODO]

This project is a fork of reflected-parameters project designed to be a stateful version.


# Build

To build, execute the following commands in project directory
```
$ gradle clean
$ gradle fatJar
```

The Jar is created under the $project/build/libs/ folder.
For more information about the build: [link](https://mkyong.com/gradle/gradle-create-a-jar-file-with-dependencies/)


# Instalation
Select the Extender tab on Burp, and click on `Add`;
![Screen Shot 2021-07-19 at 5 38 54 PM](https://user-images.githubusercontent.com/2141910/126231056-6805b699-cc6c-4ae3-ab36-5249b33ffa40.png)

Select the jar file using the top `Select file ...` button;
![Screen Shot 2021-07-19 at 5 39 00 PM](https://user-images.githubusercontent.com/2141910/126231187-8d442260-231f-49e9-8c3c-891526e5d853.png)

After successfully loading the extension a new tab called `Stateful Reflection` will show.
![Screen Shot 2021-07-19 at 5 39 23 PM](https://user-images.githubusercontent.com/2141910/126231466-6a832cfe-a181-4737-8f0d-b9e01e7b7a69.png)



# How does it work?

1. Analyze In Scope Http responses, registering the returned json values in memory (but, process only responses from Proxy).
2. Look for refections in the following In Scope HttpRequests
   * Here, we consider values in header and body.


You can use the following API for test purpose: https://repl.it/@Ailtonda/RESTserver#index.js
* Producer: https://restserver.ailtonda.repl.co/
* Consumer: https://restserver.ailtonda.repl.co/id123?id=id123
