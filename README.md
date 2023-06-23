# ETWhound

ETW hound is a collection program written in C# which reads a number of ETW sources in Windows. primarily, Security Events, Network, Process, SMB provider events are listened to.  An attempt has also been made to listen to Named Pipe Events using Windows API.

ETW collection is implemented using Microsoft Krab Setw library. Event notification feature is used to listen for events from multiple ETW providers.  For Named pipe monitoring, tdevmon.sys IO driver is used to sniff the named pipe events.

The code is implemented as a console program. it is not yet production ready and it is meant to be used in compromise assessments. if CTRL-C is pressed, it would provide Cypher Query Output which can be loaded in to neo4j.
