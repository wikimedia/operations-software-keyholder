Keyholder
=========

keyholder provides a means of allowing a group of trusted users to use a
shared SSH identity without exposing the identity's private key.

The agent binds the socket at this address by default

::

    /run/keyholder/agent.sock (0666)

Before the shared SSH agent can be used, it must be armed by a user with
access to the private key. This can be done by running:

::

    $ /usr/sbin/keyholder arm

Users in the trusted group can use the shared agent by running:

::

    $ SSH_AUTH_SOCK=/run/keyholder/agent.sock ssh remote-host ...

License
-------

`Apache 2.0 <https://www.apache.org/licenses/LICENSE-2.0>`__
