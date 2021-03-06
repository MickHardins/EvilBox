# Prerequisite #
- Java (tested with jdk 1.8)
- Gradle

Please refer to [Gradle installation guide](https://docs.gradle.org/current/userguide/installation.html) for instruction for your OS.

# Building #
Open a terminal and navigate to the project directory, there's a build.gradle file inside.
Then just enter:

```bash
gradle build
```

and wait for the buil process to complete.

# Running the application #

There are two ways to start the application:
1. Launching the main .class file 
2. Launching the .jar generated by gradle


#### Launching the Main .class file ##
1. navigate to */build/classes/main*
2. add all .jar inside */lib* folder to your class path:
	- */lib*
	- */lib/commons-cli-1.3.1*
	- */lib/classes/main*
3. specify the fully qualified package name of app's main class

If you didn't change the default directory structure of the project the following command should launch the application:

##### Linux/MacOS #####
-----------
```bash
java -cp ./:../../../lib/*:../../../lib/commons-cli-1.3.1/* com.evilbox.ApplicationMain
```

##### Windows #####
----------

```bash
java -cp ./;../../../lib/*;../../../lib/commons-cli-1.3.1/* com.evilbox.ApplicationMain
```

**Note:** if the above commands don't works try to surround classpath declaration with double or single quotes

#### Launching  the .jar file ####

If the build succedeed, gradle creates a redistributable jar of application inside the */build/application/* folder
To launch the app:
1. navigate to */build/application*
2. open a terminal, then type:

```bash
java -jar evilBox-1.0.jar
```

# Usage #

run the program with -h --help switches for usage


