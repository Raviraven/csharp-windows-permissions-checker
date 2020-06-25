# Windows Permission Checker

## Overview

Simple console app written in C# (.NET Framework), for testing (write) permissions to files and directories.  

Method "hasWriteAccess" - gets all permissions for current user (allow and deny separately), then calculates whether user has write access to those.  

## How-to

Download or clone the project and build the solution.  
After building, go to your **bin** and then (based on build configuration you use) go to eg. **Debug** directory.  
**Create folders and files** for which you want to check your access, **add current user** to permissions list and include created **directories in code**.  

Run app from IDE (the best way to catch Exception 😄) and...
it's done. ☺️
