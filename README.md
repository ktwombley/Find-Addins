# Find-Addins
   Find Office addins installed by your users. It includes COM Addins, VSTO Addins, and Web Addins.
# Description
   Find-Addins checks the registry and scans user %APPDATA% folders looking for Office Add-Ins.

   Use it to detect unexpected Add-Ins; such as those installed by a malicious user. See Technique 3 in [Covert Attack Mystery Box: A Few Novel Techniques for Exploiting Microsoft Features](https://www.slideshare.net/dafthack/covert-attack-mystery-box-a-few-novel-techniques-for-exploiting-microsoft-features)

   For best results, run as a user with Administrator privileges. When run as an unprivileged user, Find-Addins.ps1 will only reliably find Addins either installed for the current user or all users.
# Examples
   Find-Addins.ps1
   
   Find-Addins.ps1 -OutPath C:\Temp\addinscan.csv
   
# Thanks
   * Thanks to [@dafthack](https://github.com/dafthack) and [@ustayready](https://github.com/ustayready) for exposing the need for a script like this (and the awesome talk at Wild West Hackin Fest 2018)
   * Swamprat
   * LadyCoder2098
   * [@chono91](https://github.com/chono91)
   * [@captaingig](https://github.com//captaingig)
   * Friend who forbid me from crediting them
