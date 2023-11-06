# Sensitive Discoverer

> Burp Suite extension to scan for sensitive strings in HTTP messages

<!-- TOC -->
* [Sensitive Discoverer](#sensitive-discoverer)
  * [Introduction](#introduction)
    * [Features](#features)
    * [Screenshots](#screenshots)
    * [About the used regexes](#about-the-used-regexes)
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

Burp Suite is a useful tool used to do web application security testing.
While providing a lot of useful functionalities; when it comes to scanning the content inside HTTP messages against
many different patterns, this becomes a tedious process.

`Sensitive Discoverer` is a Burp Suite extension that solves this problem.
With this extension you can automatically and quickly search for sensitive strings in all HTTP messages.

Behind the curtains it all comes down to a list of Regular Expressions that get matched against the content in each HTTP message.
The extension is available with a pre-defined set of Regular Expressions divided into useful sections; but you can also add your custom lists if preferred.

### Features

- Multithreaded scan of messages
- Pre-defined sets of regexes
- Many filters to skip irrelevant messages
- Customizable regexes lists
- Export findings to CSV/JSON files
- Import/Export regexes lists from CSV/JSON files

### Screenshots

The **Logger tab**, as the Main page, contains the results of the scans:

![Logger tab](images/tab-logger.png)

The **Options tab** where to configure options and filters for the scanner:

![Options tab](images/tab-options.png)

### About the used regexes

We aim to provide a default set of regexes that can be used in as many cases as possible without numerous false positives.

As the source, many regexes are written by us. Any other should have the appropriate mention in the [References](#references) section.

To improve the matching results and reduce the scans time, each HTTP Proxy's message is divided into sections that can be matched independently.
As of now, there are five sections:

- Request
  - Request URL
  - Request Headers
  - Request Body
- Response
  - Response Headers
  - Response Body

The extension works with two lists of regexes.
One list is for general regexes, which only match within the Response sections;
The other is for filename extensions and only match against the Request URL.

## Installation

### Using the BApp Store

The extension is available [in the BApp Store](https://portswigger.net/bappstore/81e073a640964b2ea3af0da93d048dbd) inside Burp's Extender tab

### Manual install

To install the "Sensitive Discoverer" extension manually:

1. Download newest "Sensitive Discoverer" from the [GitHub Release page](https://github.com/CYS4srl/SensitiveDiscoverer/releases).
2. In BurpSuite, go to Extender -> Extension. Click Add. Ensure "Extension type" is set to Java and set the path to the .jar downloaded in step 1.
3. "Sensitive Discoverer" should appear inside Burp Extension list, and as a new tab in the top menu.

## Usage

The default configuration already has a list of regular expressions and file extensions.

To see the predefined list go to the Options tab. There you can choose which of them to activate, and you can also insert your own regular expressions.

These are the actions available to manage the lists:

- **Enable all**: disable all the regexes in the current section.
- **Disable all**: enable all the regexes in the current section.
- **List > Reset default list**: the list will be reset to the default list.
- **List > Clear list**: the list will be emptied.
- **List > Open list...**: a pop-up will appear to import a list of regex or extensions from a `csv` or `json` file. For the required file format, refer to the [Importing Lists](#importing-lists) section.
- **List > Save list...**: a pop-up will appear to save the current list of regex to a `csv` or `json` file.
- **Regex > New regex**: a pop-up will appear to insert a new regex.
- **Regex > Edit selected**: a pop-up will appear to modify the currently selected regex.
- **Regex > Delete selected**: the currently selected regex will be deleted from the list.

After customizing the lists it is now possible to start scanning for sensitive information inside HTTP messages.
The extension parses all HTTP messages captures up to that moment in the Proxy tab, and tries to match all active patterns.

### Importing Lists

Using the "Open list" and "Save list" buttons it's possible to import custom lists, and save the current list to a file.

Both `CSV` and `JSON` files with their respective extensions are supported.

- For **CSV** files, the first line represent the header line `"description","regex"` and each next line represents an entry. Entries must have the following format: `"Description","Regex"`. The quotation marks and the comma are required. Any double-quote inside the fields must be escaped with another double-quote. E.g.:

  ```csv
  "description","regex"
  "Google e-mail","\w+@gmail.com"
  ```

- For **JSON** files, the file must be in the following format:
  
  ```json
  [
    {
      "description": "Google e-mail",
      "regex": "\\w+@gmail.com"
    }
  ]
  ```

Regexes must be compliant with the Java's Regexes Style. If in doubt, use [regex101](https://regex101.com/) with the `Java 8` flavour to test regexes.

## How to compile from source code

### Using Maven from CLI

Run the following command:

```bash
mvn clean package
```

The compiled extension will be in the "/target" folder.

## About us

Since 2014 we have been working with our customers to shield their critical business infrastructures. We are qualified security specialists with a strong commitment to addressing our clients' needs, and keeping them secured against today's cyber threats.

Check out [our site](https://cys4.com/) and [our blog](https://blog.cys4.com/) for more information.

## References

The following is a list of sources for some regexes used in this extension. Many thanks to all!

- https://github.com/eth0izzle/shhgit
- https://github.com/streaak/keyhacks
