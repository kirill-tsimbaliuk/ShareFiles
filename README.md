# ShareFiles
A small utility to send files using elliptic curve encryption. The program was created as part of the work on an individual project.

## Installation
Select the installation file for your system, download and run. The installation process will begin.

## Using
After installation, you can use the program to send and accept files.

To transfer files, the receiver must run the following command:

```
sharefiles --command up --output {output-directory-path}
```
Which will start the file receiving service

The sender uses the following command
```
sharefiles --command send -f {file-path} -t {target-computer-ip}
```

To find out which computers are ready to receive files on your network, you can run the command:

```
sharefiles --command scan
```

It is also the default command that runs if you call ```sharefiles```


## For developers
The file *protocol.py* represents the entire source code of the program. You can download it and use it for your needs, it requires only one library, which is listed in requirements.txt