AIaaS
=====
README

Architecture:
Thin client written in java for cross platform.
Server side written in python.
Communicate with RESTful API and Jason objects

Server app has three parts:

Thin client records an audio file from the user and sends it to the controller endpoint.

Controller receives audio file from thin client.
Controller creates a user object with information on OS and IP address.
Controller sends audio file and the user object to the speech center.

Speech center performs speech recognition, then sends mostly empty command object and the user object to the learning center.

Learning center receives the text and the user information object and uses machine learning and the database to find the correct command.
Once the command is found, the learning center stores the command object in the database.
The learning center sends the command object and the user object to the speech center.

The speech center uses the command object and text to speech to create the resulting audio file.
The audio file is part of the command object.

The command object and the user object are passed to the controller, who sends the command object to the thin client as JSON.

The thin client executes the commands and plays the audio file.

Potential command object structure:
{
    ID: idnumber
    Input:
    {
        Audio: 'audiofilebinary',
        Text: 'commandtext'
    },
    Output:
    [
            {
                ID: 'idnumber'
                CommandName:  'commandname',
                Weight: 'percentagechancecorrect',
                Audio: 'audiofilebinary',
                Text: 'commandtext'
            },
            ...
    ],
    Timestamp: timestamp,
    OS: 'operatingsystem',
}
