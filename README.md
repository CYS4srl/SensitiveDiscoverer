# CYS4-SensitiveDiscoverer

## Introduction

Burp Suite is a useful tool used to do web application security testing. While Burp Suite provides a lot of
functionalities, it does not offer the opportunity to scan for particular pattern or file extension inside HTTP messages
and is very tedius to check every message manually.
CYS4-SensitiveDiscoverer is a Burp Suite tool used to extract Regular Expression or File Extension form HTTP response automatically or
at the end of all tests or during the test. The plugin will be available with a pre-defined set of Regular Expression
and File Extension, but the you can choose which of them activate or deacvtivate and also create your own lists.

## Installation

To install CYS4-SensitiveDiscoverer manually, you have to:

1. Download newest CYS4-SensitiveDiscoverer from the Release page
2. Go to Extender -> Extension. Click Add. Set Extension type to Java. Set the path of the file download at step 1.
   inside Extension file (.jar)
3. CYS4-SensitiveDiscoverer should appear inside Burp Extension list. Also you will see a new tab.

## Usage

The default configuration has a list of regural expression and file extension. To see the predefined list go to Options
TAB. Here you can choose which of them activate or not or you can choose to insert your own regular expression or file
extension. For both of them there are a list of actions to interact with them The actions are:

- **Reset**: the plugin will reset the default list of regular expression or file extension.
- **New**: a pop-up will appear and offer the opportunity to insert a new regular expression or file extension.
- **Delete**: after selecting a row, this will be deleted from the list.
- **Clear**: the plugin will clear the list leave them empty.
- **Open**: a pop-up will appear and offer the opportunity to insert in bulk a list of regular expression or file
  extension from a file.
- **Save**: the plugin offer the possibility to save your custom list for future tests. After you have select your own
  desired configuration you can start to find sensitive informations inside HTTP messages. The plugin will be execute in
  two different modes:

1. **Analyze HTTP History**: the plugin will parse all http history generated from that moment and it will find any
   active pattern
2. **Live**: the plugin will parse request by request as the user will generates one from his web browser.

## Credits

CYS4 was born in 2015 from a collaboration with an Israeli company in the world of Cyber ​​Security, then detaching its team ensuring the focus on innovation and quality towards a national context.

Check out our [blog](https://blog.cys4.com/) for more information.

## References

- [shhgit](https://github.com/eth0izzle/shhgit/blob/master/config.yaml): Regex and File Extension database used in this project.


