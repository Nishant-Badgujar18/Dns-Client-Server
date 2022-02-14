# Dns-client-server

* DNS Server: supporting all types of queries and replies. Should be able to do both recursive and iterative queries. Caching to be implemented.
* Client like nslookup: as close as possible to the existing nslookup, all options, all functionality, use of the file /etc/resolv.conf

# Run:

To compile and run the code

* Run the server in one terminal by typing the command 'python3 dns-server.py'. On the other terminal run client side commands one by one.

# Features:

* Types of queries: a, aaaa, cname, ns, mx, ptr, any
* Inverse(reverse) queries
* Set a server other than the default.
* Set a port number other than the default.
* Set timeout for the request
* Set recursive or non-recursive queries
* Find the values of all parameters(server, port, timeout, query type, class)
* Caching of responses at the local dns server according to their time to live.
