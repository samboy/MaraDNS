# MaraDNS automated testing

The original intent here is to set up a Docker image which can
run MaraDNS on any system which supports Docker.

Right now, This is a series of files which allow a system running 
MaraDNS to run automated tests every day.  Because we use 
Docker/Podman to run the tests, we can run the tests using just a 
single cron job on a bog standard Posix compliant *NIX system 
with Docker or Podman support.

# Setting up the tests

Make sure Docker is installed and running, then:

```bash
./make.docker.image.sh
```

This `make.docker.image.sh` script will make a Docker image
which can run the MaraDNS automated tests.

Once the image is made, set up an empty directory where the tests
will be run.  Edit `run.MaraDNS.tests` to have `TESTDIR` point
to that directory.  Next, run `docker images` and look for a
repository with a name like `maradns-2020-07-26`; on that
line there should be an image ID like `0a0b0c1d1e1f`.  Edit
`run.MaraDNS.tests` to have `IMAGE` image point to that image ID.

The Docker image does not need to be frequently updated; the
automated tests pull MaraDNS from GitHub to run the actual tests
against.

# Running the tests

At this point, the tests are ready to run:

```bash
./run.MaraDNS.tests
```

Have a cup of coffee; it takes about an hour to run all of the
tests.

The script is smart enough to not run the tests again unless
MaraDNS has been updated since the last time one ran the tests.

# Setting up a cron job

These tests should be easy enough to set up to run in Jenkins.
I actually do not use Jenkins to run the tests; my personal Linux
server runs the tests via cron (scheduled tasks in *NIX systems) 
every morning.

To make a crontab, after setting up the directory and, as root, 
copying `run.MaraDNS.tests` over to `/usr/local/bin/`, type in 
`crontab -e` (one does *not* need to be root to edit crontabs on 
Ubuntu 20.04 LTS, but some systems require one to set up permissions before
a non-root user to run cron tabs; your mileage may vary).  If one is 
not comfortable editing files with `vi`, type in `export EDITOR=nano` 
before making the crontab.  Make a line which looks like this:

```
32 5 * * * /usr/local/bin/run.MaraDNS.tests
```

This line says every morning, at 5:32am (32: Minutes after the hour;
5: Hour of the day; `* * *`: Every day), we run 
`/usr/local/bin/run.MaraDNS.tests`

After the tests are run, look for a file with a name like
`output-2020-07-26` in the `TESTDIR` directory set up above
(see the section "Setting up the tests").  This file will have
the test output.

# Podman compatibility

These directions will *mostly* work on the Podman Docker clone.  However,
the script `run.MaraDNS.tests` will needed to be edited before things
run in Podman to invoke a Podman container with the `-it` flag, e.g.

```
docker run -it $IMAGE /run.tests.sh > output-$( date +%Y-%m-%d )
```

The `-it` is *not* needed if using Docker; it’s only needed for Podman.

