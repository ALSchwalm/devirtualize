The basics
===========

``Devirtualize`` is an IDA plugin that rebuilds type information from the vtables
and RTTI embedded in a binary. This information can then be used to 'devirtualize'
virtual function calls. Some additional features are provided like viewing
inheritance graphs.

Requirements
------------

``devirtualize`` was written using IDA Pro 6.95. It may work with earlier versions
but has not been tested. Additionally, the plugin makes use of the IDA Decompiler
features, so the user must have a license for that.

Installation
------------

Because the project is built using the IDA python interface, there is no need for
compilation. Just copy the ``devirtualize`` folder and ``devirtualize_main.py``
file into your ida ``plugins`` directory.

Usage
-----

Most features of the plugin will require that the user has first run the vtable
analysis. To do this go to ``Edit->Plugins->Devirtualize``. This process may
take several minutes. After the analysis is completed, structures for each recovered type will be
present in the ``Structures`` window in IDA.

The actual devirtualization will occur automatically. When you have set the
type of a local variable, the plugin will devirtualize anything it is able to
using that information.
