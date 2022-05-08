![example workflow](https://github.com/AlexeyInc/Brute-force-protector/actions/workflows/go-ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/AlexeyInc/Brute-force-protector/branch/main/graph/badge.svg?token=38P1KBTAQM)](https://codecov.io/gh/AlexeyInc/Brute-force-protector)
&nbsp;[![Linkedin](https://i.stack.imgur.com/gVE0j.png) LinkedIn](https://www.linkedin.com/)
&nbsp;


# Brute-force-protector
### The service is designed to protect from brute force attack during authorization in any system. 

### Program use cases: 
- Authorization check
- Bucket reset
- Add/Remove IPNet to white/black lists
- Predefined white and black subnets in assets folder

## How launch project: 

Command `make run` will automatically download all nessesarry dependencies and launch the project in docker container. <br />
Command `make stop` will remove all project containers from docker environment. <br />
Command `make test` will launch unit tests <br />
Command `make integration-test` will launch the project, run integration tests and clear all docker containers after tests is done. <br />

## How to use CLI:

CLI have 3 main commands: 
`authorize` — to make authorize request
`reset` — to reset some bucket by key
`reserve` — to maintain white and black subnetworks lists

- cmd `authorize` take 3 params which represents login, password and ip <br />
- cmd `reset` take 2 params which represent login and ip (to skip some param pass empty string «» insted) <br />
- cmd `reserve` have 2 flags: `--action` (value: **add** or **remove**) and `--list` (value: **white** or **black**). 
(Without any flags by default command `reserve (your subenet)` will automatically try to add subnet to white list)

#### Example of commands: 
	bf-cli authorize SomeLogin pass123 123.123.123.111
	bf-cli reset SomeLogin «»
	bf-cli reserve -a=add -l=black 100.100.0.0/16
	
Local unit test coverage: 
![image](https://user-images.githubusercontent.com/29926552/167132910-b10e8cde-dd14-4c12-851e-66420cd2ec28.png)

