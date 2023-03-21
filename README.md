# SensitiveDiscoverer

> Burp Suite extension to scan for sensitive strings in HTTP messages

<!-- TOC -->
* [SensitiveDiscoverer](#sensitivediscoverer)
  * [Introduction](#introduction)
    * [Features](#features)
    * [Screenshots](#screenshots)
  * [Installation](#installation)
    * [Using the BApp Store](#using-the-bapp-store)
    * [Manual install](#manual-install)
  * [Usage](#usage)
    * [Importing Lists](#importing-lists)
  * [How to compile from source code](#how-to-compile-from-source-code)
    * [Using Maven from CLI](#using-maven-from-cli)
  * [About us](#about-us)
  * [References](#references)
<!-- TOC -->

## Introduction

Burp Suite is a useful tool used to do web application security testing. While Burp Suite provides a lot of functionalities, it does not offer the opportunity to scan for particular pattern or file extensions inside HTTP messages. Checking every message by hand can be a very tedious process.

`SensitiveDiscoverer` is a Burp Suite extension that solves this problem. With this extension you can automatically search sensitive strings in HTTP messages.

It uses a list of Regular Expressions and File Extensions to match for in each message. The plugin is available with a pre-defined set of Regular Expression and File Extensions, but you can also add your custom lists.

### Features

- Multithreaded scan of messages
- Pre-defined set of regex
- Many filters to skip irrelevant messages
- Customizable regexes lists
- Import/Export regexes with CSV files

### Screenshots

Main page with the results of the scan:

![Logger tab](images/tab-logger.png)

Options tab to configure filters and scanner options:

![Options tab](images/tab-options.png)

## Installation

### Using the BApp Store

The extension is available in the BApp Store inside Burp's Extender tab

### Manual install

To install the SensitiveDiscoverer extension manually:

1. Download newest SensitiveDiscoverer from the Release page.
2. Go to Extender -> Extension. Click Add. Set Extension type to Java. Set the path of the (.jar) to the file downloaded at step 1.
3. SensitiveDiscoverer should appear inside Burp Extension list, and a new tab will appear.

## Usage

The default configuration already has a list of regular expressions and file extensions.

To see the predefined list go to the Options tab. There you can choose which of them to activate, and you can also insert your own regular expressions.

These are the actions available to manage the lists:

- **New**: a pop-up will appear to insert a new regex or extension.
- **Delete**: the currently selected row will be deleted from the list.
- **Clear**: the list will be emptied.
- **Reset**: the plugin will reset to the default list.
- **Open**: a pop-up will appear to import a list of regex or extensions from a `.csv` file. For the required file format, refer to the [Importing Lists](#importing-lists) section.
- **Save**: the current list will be saved to a `.csv`.
- **Enable all**: disable all the regexes in the current section.
- **Disable all**: enable all the regexes in the current section.

After customizing the lists it is now possible to start scanning for sensitive information inside HTTP messages. The plugin offers the following mode of operations:

1. **Analyze HTTP History**: the plugin will parse all http history generated up to that moment, matching all active patterns.

### Importing Lists

Using the "Open" and "Save" buttons it's possible to import custom lists, and save the current list to a file.

The files must have the `.csv` extension.

Each line in the file represents an entry and should have the following format: `"Description","Regex"`. The quotation marks and the comma are required.

Regexes must be compliant with the Java's Regexes Style. If in doubt, use [regex101](https://regex101.com/) with the `Java 8` flavour to test regexes.

## How to compile from source code

The extension was compiled with OpenJDK 17.

The BApp can be compiled with Maven by following these steps:

1. View > Tool Windows > Maven.
2. On the new right panel expand the Lifecycle folder.
3. Double-click on install.

The compiled extension will be in the "/target" folder.

### Using Maven from CLI

As an alternative, run the following command:

```bash
mvn clean package
```

## About us

Since 2014 we have been working with our customers to shield their critical business infrastructures. We are qualified security specialists with a strong commitment to addressing our clients' needs, and keeping them secured against today's cyber threats.

Check out [our site](https://cys4.com/) and [our blog](https://blog.cys4.com/) for more information.

## References

- [shhgit](https://github.com/eth0izzle/shhgit/blob/master/config.yaml): Regexes and File Extensions lists used in this project.
