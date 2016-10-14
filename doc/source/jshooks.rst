.. _jshooks:

JS Hooks
========

Starting from version 0.8.2, Thug features JavaScript hooks. This feature could be quite useful
if you are required to load your own JavaSript code in a page to be analyzed. For instance, if 
you are interested into scanning JavaScript libraries to detect known vulnerabilities (take a look 
at RetireJS [#f1]_ for a great example of that) this feature could be quite handy.

Defining and using JS hooks is extremely simple. 

If you need to execute just one JavaScript file just drop it in the directory */etc/thug/hooks* and 
you are done. 

If you need to execute more than one Javascript file, be aware that Thug can enforce the order of
execution of such files. All you need to do is to sort the file names in alphabetical order and 
Thug will execute them in that order. A good practice I would like to suggest is to prefix each file 
name with a numerical prefix (and remember that the string '10' is lesser than '9' so use '09' instead 
if you have to execute more than nine hooks). 

Let's take a look at an example. We will make use of the following simple page. 

.. code-block:: javascript

    <!DOCTYPE html>
    <html>
    <body>
        <script type="text/javascript">
        strVar = "one";
        myVar = eval("strVar");
        alert(myVar);
        </script>
    </body>
    </html


Let's run Thug against it

.. code-block:: sh

    ~ $ thug -l test.html 
    [2016-10-14 10:21:47] [Window] Alert Text: one

Let's now drop the file 1-hook.js in the folder */etc/thug/hooks* and run Thug again

.. code-block:: sh

    ~ $ ls -lh /etc/thug/hooks/
    total 4.0K
    -rw-r--r-- 1 root root 35 Oct 14 10:22 1-hook.js

    ~ $ cat /etc/thug/hooks/1-hook.js 
    function eval() {
            return "two";
    }

    ~$ thug -l test.html 
    [2016-10-14 10:22:58] [Window] Alert Text: two

It's easy to realize that the eval method was hooked. Let's now drop the file 2-hook.js in 
the folder */etc/thug/hooks* and run Thug again

.. code-block:: sh

    ~$ ls -lh /etc/thug/hooks/
    total 8.0K
    -rw-r--r-- 1 root root 35 Oct 14 10:22 1-hook.js
    -rw-r--r-- 1 root root 37 Oct 14 10:26 2-hook.js

    ~$ cat /etc/thug/hooks/2-hook.js 
    function eval() {
            return "three";
    }

    ~ $ thug -l test.html 
    [2016-10-14 10:26:45] [Window] Alert Text: three

The two scripts are executed in the right order and the hook defined in 2-hook.js overwrites the 
one defined in 1-hook.js as expected. Let's now drop the file 3-hook.js in the folder */etc/thug/hooks* 
and run Thug once again

.. code-block:: sh

    ~ $ ls -lh /etc/thug/hooks/
    total 12K
    -rw-r--r-- 1 root root 35 Oct 14 10:22 1-hook.js
    -rw-r--r-- 1 root root 37 Oct 14 10:26 2-hook.js
    -rw-r--r-- 1 root root 36 Oct 14 10:28 3-hook.js

    ~ $ cat /etc/thug/hooks/3-hook.js 
    function eval() {
            return "four";
    }

    ~ $ thug -l test.html 
    [2016-10-14 10:28:20] [Window] Alert Text: four

The three scripts are executed again in the right order and the hook defined in 3-hook.js
overwrites the other ones as expected.

.. [#f1] `RetireJS <https://github.com/retirejs/retire.js>`_ is a scanner detecting the use of JavaScript libraries
         with known vulnerabilities
