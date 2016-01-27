<?php
/*
phpGSB - PHP Google Safe Browsing Implementation
Released under New BSD License (see LICENSE)
Copyright (c) 2010-2015, Sam Cleaver (Beaver6813, Beaver6813.com)
All rights reserved.

INITIAL INSTALLER - RUN ONCE (or more than once if you're adding a new list!)
*/
require("phpgsb.class.php");
$phpgsb = new phpGSB("DATABASE_NAME","DATABASE_USERNAME","DATABASE_PASSWORD");

//Install MySQL tables
$phpgsb->install();
	
        
        