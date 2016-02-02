# PHP Implementation of Google Safe Browsing V3

This is a fork of **samclaever/phpGSB** modified to work with v 3.0 of GSB

The code is based on samcleaver/phpGSB and the python library https://github.com/afilipovich/gglsbl

* Updating of GSB lists to a MySQL database
* Basic checking of URLs' against lists and then full-hash checks against the full GSB database
* Caching of full-hash keys to minimise requests to the remote Google server



## Download

* git clone https://github.com/cminatti/phpGSB

## Installation

1. You have to install protocol buffers php extension:  https://pecl.php.net/package/protocolbuffers
2. Enter database details into install.php (Replace DATABASE_USERNAME, DATABASE_NAME and DATABASE_PASSWORD with respective information)
3. Run install.php
4. Look at listupdater.php and lookup.php example files for basic methods on using the system.
5. If you choose to use listupdater.php as-is then set it as a cron job/scheduled task to run every minute. *(It won't actually update every minute but is required incase of backoff procedures and timeouts)*

## FAQ

* **When I do a lookup, phpGSB says the URL is safe but I know it's not.**
*The database is updated in chunks from Google's central server. Because of this, you need to run updates for 24 hours before you can start doing lookups, this is a limitation of the specification and not the implementation. (Check Step 5 of installation on how to ensure updates are running.)*

## License

The phpGSB library is released under the New BSD License.

```
Copyright (c) 2010-2015, Sam Cleaver

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the organization nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
