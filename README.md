# Nanoblog - self-hosted microblog

Nanoblog is a simple and professional blog with a 280 character limit that supports crossposting to your Twitter account. Posts can also be buffered for automatic publication on a selected schedule to keep your blog and Twitter account fresh.

After adding Nanoblog, start writing blog posts, creating threads, and crossposting to Twitter by connecting your account.

![Screenshot](https://raw.githubusercontent.com/nanoblog/nanoblog/master/screenshot1.png)

[Demo](https://blog.portal.cloud/)

## Features

* **Blogging on Easy Mode**
  * 280 character limit makes blogging accessible to everyone and threading makes it possible to write more when desired.
* **Buffered Posts**
  * Add posts to your buffer to automatically publish on a selected schedule.
* **Twitter Crossposting**
  * Add your Twitter account to enable crossposting to your Twitter timeline.
* **Threaded Posts AKA tweetstorms**
  * Click the “Add another update” button to enable thread posting.
* **Web Analytics**
  * Add javascript tracking code to your blog posts for web analytics.

## Run Nanoblog on Portal Cloud

Portal Cloud is a hosting service that enables anyone to run open source cloud applications.

[Sign up for Portal Cloud](https://portal.cloud/) and get $15 free credit.

## Run Nanoblog on a VPS

Running Nanoblog on a VPS is designed to be as simple as possible.

  * Public Docker image
  * Single static Go binary with assets bundled
  * Automatic TLS using Let's Encrypt
  * Redirects http to https
  * No database required

### 1. Get a server

**Recommended Specs**

* Type: VPS or dedicated
* Distribution: Ubuntu 16.04 (Xenial)
* Memory: 512MB or greater

### 2. Add a DNS record

Create a DNS record for your domain that points to your server's IP address.

**Example:** `nanoblog.example.com  A  172.x.x.x`

### 3. Enable Let's Encrypt

Nanoblog runs a TLS ("SSL") https server on port 443/tcp. It also runs a standard web server on port 80/tcp to redirect clients to the secure server. Port 80/tcp is required for Let's Encrypt verification.

**Requirements**

* Your server must have a publicly resolvable DNS record.
* Your server must be reachable over the internet on ports 80/tcp and 443/tcp.

### Usage

**Example usage:**

```bash
# Download the nanoblog binary.
$ sudo wget -O /usr/bin/nanoblog https://github.com/nanoblog/nanoblog/raw/master/nanoblog-linux-amd64

# Make it executable.
$ sudo chmod +x /usr/bin/nanoblog

# Allow it to bind to privileged ports 80 and 443.
$ sudo setcap cap_net_bind_service=+ep /usr/bin/nanoblog

$ nanoblog --http-host nanoblog.example.com
```

### Arguments

```bash
  -backlink string
    	backlink (optional)
  -cpuprofile file
    	write cpu profile to file
  -datadir string
    	data dir (default "/data")
  -debug
    	debug mode
  -help
    	display help and exit
  -http-host string
    	HTTP host
  -memprofile file
    	write mem profile to file
  -version
    	display version and exit


```
### Run as a Docker container

The official image is `nanoblog/nanoblog`.

Follow the official Docker install instructions: [Get Docker CE for Ubuntu](https://docs.docker.com/engine/installation/linux/docker-ce/ubuntu/)

Make sure to change the `--env NANOBLOG_HTTP_HOST` to your publicly accessible domain name.

```bash

# Your data directory must be bind-mounted as `/data` inside the container using the `--volume` flag.
# Create a data directoy 
$ mkdir /data

docker create \
    --name nanoblog \
    --restart always \
    --volume /data:/data \
    --network host \
    --env NANOBLOG_HTTP_HOST=nanoblog.example.com \
    nanoblog/nanoblog:latest

$ sudo docker start nanoblog

$ sudo docker logs nanoblog

<log output>

```

#### Updating the container image

Pull the latest image, remove the container, and re-create the container as explained above.

```bash
# Pull the latest image
$ sudo docker pull nanoblog/nanoblog

# Stop the container
$ sudo docker stop nanoblog

# Remove the container (data is stored on the mounted volume)
$ sudo docker rm nanoblog

# Re-create and start the container
$ sudo docker create ... (see above)
```

## Help / Reporting Bugs

Email support@portal.cloud

