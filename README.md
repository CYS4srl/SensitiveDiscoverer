# CYS4-SensitiveDiscoverer

> Burp Suite extension to scan for sensitive strings in HTTP messages.

## Introduction

Burp Suite is a useful tool used to do web application security testing. While Burp Suite provides a lot of
functionalities, it does not offer the opportunity to scan for particular pattern or file extensions inside HTTP messages. Checking every message by hand can be a very tedious process.

`CYS4-SensitiveDiscoverer` is a Burp Suite extension that solves this problem. With this extension you can automatically search sensitive strings in HTTP messages. It uses a list of Regular Expressions and File Extensions to match for in each message.

The plugin is available with a pre-defined set of Regular Expression and File Extensions, but you can also add your custom lists.

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
mvn clean install
```

## Installation

To install CYS4-SensitiveDiscoverer manually, you have to:

1. Download newest CYS4-SensitiveDiscoverer from the Release page.
2. Go to Extender -> Extension. Click Add. Set Extension type to Java. Set the path of the (.jar) to the file downloaded at step 1.
3. CYS4-SensitiveDiscoverer should appear inside Burp Extension list. A new tab will also appear.

## Usage

The default configuration has a list of regular expression and file extension.

To see the predefined list go to the Options tab. There you can choose which of them to activate and you can also insert your own regular expressions.

These are the actions to manage the list:

- **Reset**: the plugin will reset the default list of regular expression or file extension.
- **New**: a pop-up will appear and offer the opportunity to insert a new regular expression or file extension.
- **Delete**: after selecting a row, this will be deleted from the list.
- **Clear**: the plugin will clear the list leave them empty.
- **Open**: a pop-up will appear and offer the opportunity to insert in bulk a list of regular expression or file extension from a file.
- **Save**: the plugin offer the possibility to save your custom list for future tests. After you have select your own desired configuration you can start to find sensitive information inside HTTP messages. The plugin will be execute in two different modes:

  1. **Analyze HTTP History**: the plugin will parse all http history generated from that moment and it will find any active pattern.
  2. **Live**: the plugin will parse request by request as the user will generates one from his web browser.

## Credits

CYS4 was born in 2015 from a collaboration with an Israeli company in the world of Cyber Security, then detaching its team ensuring the focus on innovation and quality towards a national context.

Check out [our blog](https://blog.cys4.com/) for more information.

## References

- [shhgit](https://github.com/eth0izzle/shhgit/blob/master/config.yaml): Regex and File Extension database used in this project.
