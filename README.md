# weeve_clients
Weeve platform clients for weeveOS

## host folder
The source code for the normal world application in weeveOS.

## ta folder
The source code for the trusted world application in weeveOS.

# How to run

## Contents
1. [Introduction](#introduction)
2. [Join Marketplace](#marketplace)
3. [Pull Docker Image](#dockerimage)
4. [Run weeve client](#weeveclient)
5. [Exploring the weeve platform](#weeveplatform)
  * [How to see your successful trades?](#weeveplatform1)
  * [What happens underneath the weeveOS?](#weeveplatform2)
6. [Hardware Recommendations] (#hardware)

## <a name="introduction"></a>Introduction
Weeve’s vision is to empower the Economy of Things where IoT machines (or “weeves” thereof) index, process and trade harvested data against digital assets, most notably crypto coins. We envision public or private marketplaces for any form of digital asset ranging from geo-data to electricity or delivery status, where data producers and consumers (resp., buyers and sellers) come together, escrow their supply and demand, and fairly exchange their digital assets for agreed upon prices.

We have designed and developed two foundational technologies - the weeve OS and weeve Platform - to implement the vision of IoT data commercialization. weeveOS is the first lightweight IoT-Blockchain Operating System. It runs on commodity IoT hardware supporting the ARM Trustzone extension and aims at bridging the gap between IoT and Blockchains. It uses cutting-edge security technologies inspired by recent advances in cryptographic research to ensure
  * trustworthy sensing and processing,
  * authentic and confidential transportation, and
  * non-falsifiable value assessment of IoT data.

A bit more concrete, a Trusted Execution Environment (TEE) provides the isolation of security-critical programs from non-security-critical ones. The weeveOS leverages this strong isolation mechanism to shield cryptographic operations and key material storage against corruption of the device. The weeveOS comprises the following technical features in a nutshell:
  * Secure Boot verifying the integrity of the OS at startup
  * Trusted Storage separated from the main system to protect cryptographic key material (e.g., wallet keys to sign Ethereum smart contracts) against extraction
  * Program Isolation to prevent malicious processes from harming crucial processes (e.g., disrupting the execution of cryptographic algorithms)
  * Run-Time testification of processes, e.g., to monitor the generation and processing of IoT data and safeguarding their truthfulness and integrity
  * 3-round communication and battery efficient communication protocol to securely transport digital assets to marketplaces (dubbed MQTTS)
  * Blockchain Wallet isolating the signing keys and signing algorithm
  * Cryptographically secure fair exchange protocol to escrow supply and demand between IoT device through the Blockchain 

We refer the reader to the tech white paper for details <a href="http://papers.weeve.network/weeve_whitepaper.pdf" target="_blank">weeve Whitepaper</a>. 

The  weeve Platform is the core backend software. It empowers individuals, enterprises or governmental bodies to set up, curate or join existing marketplaces. An example of an energy trading marketplace can be found here <a href="http://dev.weeve.network" target="_blank">weeve marketplace</a>. Once you installed the weeveOS docker, you can register a device on the marketplace and participate in a fair exchange.

## <a name="marketplace"></a>Join our Marketplace
Go to <a href="http://dev.weeve.network" target="_blank">dev.weeve.network</a> and register yourself. Now log into the marketplace and go the the **MY ACCOUNT -> Device Curator** and start the device registration by clicking on the **ADD DEVICE** button in the bottom-left corner. Choose a name and other preferred options for your new device. At the end of the registration process you will receive a *Device ID*, which needs to be used in the registration process of the client (see: <a href="#weeveclient">Run weeve client</a>). You can also copy the Device ID after finishing the registration process by clicking on the devices' name in the device curator. 

## <a name="dockerimage"></a>Pull the Docker Image

###  MacOS, Windows

In case you want to try out our demonstrator on a non-linux-based machine you need to use a linux-based virtual machine. 
We recommend using our <a href="http://dev.weeve.network/dl/weeve-vm.ova" target="_blank">weeve VM</a> to make sure you can use all of our core features. It comes with all dependecies, to make sure that you can get started immediately! (The root password is *weeve*). 

Before running in the terminal the following *case-sensitive* instructions, it can be helpful to activate the copy&paste function of the VM via a <a href="https://www.liberiangeek.net/2013/09/copy-paste-virtualbox-host-guest-machines/">shared</a> clipboard.

Download the latest version of our weeveOS docker image (approx. 1 GB)
```
sudo docker pull weeveiot/weeveOS
```
Now the container can be run with the `docker run`command. The parameter `-p` redirects the port to your host machine. You can see the running containers with `sudo docker ps -a`.
```
sudo docker run -d -p 1883:1883 -p 1337:22 weeveiot/weeveos
```

Use ssh to establish a connection into the newly created container:

```
ssh -Y root@localhost -p 1337
```
The password is *weeve*

Please go on with the <a href="weeveclient">Run weeveOS</a> section.

### Linux

Make sure docker.io and ssh is installed on your (virtual) machine. Download the neccessary dependencies:

```
sudo apt install docker.io ssh
```

Download the latest version of our weeveOS docker image (approx. 1 GB)
```
sudo docker pull weeveiot/weeveos
```

**or** the developer version (approx. 12 GB)

```
sudo docker pull weeveiot/weeveOS:latest
```

Now the container can be run with the `docker run`command. The parameter `-p` redirects the port to your host machine. You can see the running containers with `sudo docker ps -a`.
```
sudo docker run -d -p 1883:1883 -p 1337:22 weeveiot/weeveos:latest
```

Use ssh to establish a connection into the newly created container:

```
ssh -Y root@localhost -p 1337
```
The password is *weeve*

## <a name="weeveclient"></a>Run weeveOS
You are now connected to the docker container via ssh and you are already in the right folder to get started.

Press **`c`** to boot weeveOS with in the qemu prompt.
Press **`Enter`** to start the terminal.

To start the registration process execute the program *register* (Type in **`register`** in the "normal world" terminal). When prompt enter your `Device ID` generated from the weeve marketplace (you can paste from clipboard via Ctrl+Shift+V).

Now you are connected to the marketplace and your device is sucessfully registered. If you want to produce or consume digital assets start the program **`consumer`** or **`producer`** and follow the instructions.

## <a name="weeveplatform"></a>Exploring the weeve platform

### <a name="weeveplatform1"></a> How to see your successful trades?
When two offers (a supply and a demand) are being matched by the weeve Gateway, they turn into a **Trade**. A trade that has been fulfilled properly (i.e. has been payed for) will be displayed as a **Closed Trade** in your account page.

### <a name="weeveplatform2"></a> What happens underneath the weeveOS?
 * *register*: generates cryotographic key material in the Trusted Storage for the secure communication with the marketplace, the testification of data, and the Ethereum wallet. Through a challenge-response protocol the marketplace makes sure, that the device is the owner of the keys. For demonstration purposes the marketplace/gateway will transfer 10 ETH on our testchain to every device after its successful registration.
 * *consumer* and *producer*: start an energy-trading program on your IoT device. It emulates a process of consuming or producing energy. During each iteration the secure world will inspect the normal world program flow and testify the data. The last step is sending the testified IoT data to our marketplace, where the data will be processed further as tradable digital assets
 * *unregister*: clears the credential store with all cryotographic keys and trusted storages.
 
## <a name="hardware"></a>Hardware Recommendation
If you want to experiment with trusted execution environments a good starting point would be the either the discontinued HiKey LeMaker or the <a href="https://www.96boards.org/product/hikey960/" target="_blank">HiKey 960</a>. Both devices have been tested successfully, but we appreciate any feedback on more platforms as they become available.

A good way to get in touch if you have got more questions or need further support is our <a href="https://gitter.im/weeveiot" target="_blank">gitter channel</a>.
