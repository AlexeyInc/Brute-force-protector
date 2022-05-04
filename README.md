# Brute-force-protector
### The service is designed to protect from brute force attack during authorization in any system. 

### Program use cases: 
**Authorization check, Bucket reset, Add/Remove IPNet to white/black lists**

## How launch project: 

Command `make up` will automatically download all nessesarry dependencies and launch the project in docker container. <br />
Command `make down` will remove all project containers from docker environment. <br />
Command `make integration-tests` will launch the project, run integration tests and clear all docker containers after tests is done. <br />

## How to use CLI:

CLI have 3 main commands: 
`authorize` — to make authorize request
`reset` — to reset some bucket by key
`reserve` — to maintain white and black subnetworks lists

- cmd `authorize` take 3 params which represents login, password and ip <br />
- cmd `reset` take 2 params which represent login and ip (to skip some param pass empty string «» insted) <br />
- cmd `reserve` have 2 flags: `--action` (value: **add** or **remove**) and `--list` (value: **white** or **black**). <br />
(Without any flags by default command `bf-cli reserve (your subenet)` will automatically try to add subnet to white list)

#### Example of commands: 
	bf-cli authorize SomeLogin pass123 123.123.123.111
	bf-cli reset SomeLogin «»
	bf-cli reserve -a=add -l=black 100.100.0.0/16

##### Possible improvements:

*__White/black lists check order__. <br /> Current solution have concrete order of checks on existing IP in white/black subnets lists. Firstly, we check white list, then black list. 
So if IP exist in some subnet from white list — we will allow sender to authorize and not check does this IP included in any of subnets from black list.* 

