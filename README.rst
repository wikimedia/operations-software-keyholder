Keyholder
=========

keyholder provides a means of allowing a group of trusted users to use a
shared SSH identity without exposing the identity's private key.

This is accomplished by running a pair of SSH agents as system services:
``keyholder-agent`` and ``keyholder-proxy``:

-  ``keyholder-agent`` is the actual ssh-agent instance that holds the
   private key.
-  ``keyholder-proxy`` proxies requests to the agent via a domain socket
   that is world readable. The proxy implements a subset of the
   ssh-agent protocol, allowing users to list identities and to use them
   to sign requests, but not to add or remove identities.

The two services bind domain sockets at these addresses:

::

    /run/keyholder
    |__ agent.sock (0600)
    |__ proxy.sock (0666)

Before the shared SSH agent can be used, it must be armed by a user with
access to the private key. This can be done by running:

::

    $ /usr/sbin/keyholder arm

Users in the trusted group can use the shared agent by running:

::

    $ SSH_AUTH_SOCK=/run/keyholder/proxy.sock ssh remote-host ...

License
-------

`Apache 2.0 <https://www.apache.org/licenses/LICENSE-2.0>`__
