devirtualize
============

`devirtualize` is an IDA Pro plugin for handling C++ virtual functions. It works
like this:

1. `devirtualize` locates and parses vtable information from the binary
2. It creates structures for the types associated with these tables
3. The user goes to a function and sets a local variable to have one of these types
4. `devirtualize` converts all virtual calls using that variable to normal function calls

Because the user will often not know the exact type a variable should have,
`devirtualize` can also show inheritance hierarchies and families. It is likely
the user can determine which type family the variable belongs to.

Usage
=====

Copy the "devirtualize" folder and "devirtualize_main.py" files to your IDA "plugins" 
directory. Execute the initial type construction with Edit->Plugins->Devirtualize.
After this, virtual functions will be converted whenever the plugin is able.

Documentation
=============

Documentation and additional usage info is available [here](https://devirtualize.readthedocs.io/en/latest/index.html)
