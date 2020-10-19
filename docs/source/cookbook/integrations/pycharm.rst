====================
PyCharms integration
====================

Aura can be integrated inside PyCharms by adding it as an external tool. Open the Preferences and navigate to "Tools -> External Tools" and click the add button to add a new tool.
The command you enter for running the external tool depends on the mode you want to run Aura in which is either a locally installed Aura or via a docker image. After the external tool is configured, you can right-click any file or directory in the file browser panel and select the Aura tool from a list of External Tools in the PyCharms menu to scan the selected file/directory with Aura.

.. note::
    You might need to restart PyCharms to see Aura in the list of the External Tools after you add it to the preferences.


------------------
Local installation
------------------

First, you must find out the full path of the aura executable which can be done by running ``which aura``, don't forget to enable virtual environment first where you installed Aura. Enter the following as the program argument: ``scan $FilePath$``. It is recommended to set up the working directory to the directory where your Aura config.ini is located or configure the location via an environment variable.

.. image:: /_static/imgs/integration_pycharm_local.png


----------------------------
Integration via docker image
----------------------------

Find out the full path of a docker client by running the command ``which docker``, use the output as the program path.
Enter the following as the program arguments:

``run --rm -v $FilePath$:/quarantine sourcecodeai/aura:dev scan /quarantine``

.. tip::
    You can change the `latest` docker image tag to any other version of aura that you wish to use as the integration

Set the working directory to the `$FileDir$`.

.. image:: /_static/imgs/integration_pycharm_docker.png
