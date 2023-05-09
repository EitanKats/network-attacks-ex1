# network-attacks-ex1

# Attack Tool

Evil twin attack is a type of Wi-Fi attack where the attacker sets up a fake access point that looks identical to a legitimate one in order to trick users into connecting to it. Once connected, the attacker can intercept and steal sensitive information such as login credentials, credit card numbers, and other personal data.

"setup_run.sh" that is designed to facilitate the setup and execution of an evil twin attack. It takes three arguments:
```
"--attack <attack_interface>": specifies the network interface to use for the attack (presumably the one hosting the fake access point).
"--net <net_interface>": specifies the network interface to use for the legitimate network connection (presumably the one connecting to the internet).
"--fake-ap <fake_ap_interface>": specifies the network interface to use for the fake access point.
```
The script is intended to be run with superuser privileges (via the "sudo" command) and provides an example of how to use it with sample arguments. It is important to note that the usage of this tool for evil purposes is illegal and unethical.

## Defence/Detection tool

How to run the defence tool, it is important to provide the name of the interface that will be used to identify attacks:
```
sudo python3 defence.py wlxc83a35c2e0bb
```


This is the format that the defence is accumulating the data in:

```
{
    "ap_mac1":{
        "client1": [],
        "client2": [],
        "client3": [],
        "client4": [],

    },

    "ap_mac2":{
        "client1": [],
        "client2": [],
        "client3": [],
        "client4": [],

    }

}
```

If there is a client that receives an abnormal amount of deauth frames then we alert in the tool which client is being attacked and on which AP
