# ChangeLog

| Version | Date | Description |
| --- | --- | --- |
| 0.2.00037 | 16/12/2024 | adjusted logging |
| 0.2.00036 | 08/12/2024 | fixed issue with client blocking switch |
| 0.2.00035 | 04/12/2024 | handling of offline clients |
| 0.2.00034 | 04/12/2024 | better connection session handling |
| 0.2.00033 | 04/12/2024 | fixed issue with missing state classes and missing entity units |
| 0.2.00032 | 04/12/2024 | fixed issue were device trackers were created with duplicate name |
| 0.2.00031 | 04/12/2024 | fixed issue were previous offline clients didn't received all sensors |
| 0.2.00030 | 04/12/2024 | added `Blocked` switch to clients |
| 0.2.00029 | 04/12/2024 | restructured client handling to fetch known and online clients |
| 0.2.00028 | 04/12/2024 | added sensor WireLess Linked on devices |
| 0.2.00027 | 29/11/2024 | added led setting on devices |
| 0.2.00026 | 29/11/2024 | added switches for 2.4 GHz and 5GHz radio on devices |
| 0.2.00025 | 29/11/2024 | cleanup clients without entities |
| 0.2.00024 | 29/11/2024 | fixed issue with Switches in ACL Rules and URL Filter, renaming devices |
| 0.2.00023 | 29/11/2024 | added SSID switches to AP devices |
| 0.2.00022 | 28/11/2024 | changed file encoding to utf-8 |
| 0.2.00021 | 28/11/2024 | added URL Filters |
| 0.2.00020 | 28/11/2024 | renamed device models and manufacturer |
| 0.2.00019 | 28/11/2024 | completly restructured, only Devices, Clients and ACL Rules are available at the moment, no URL Filters and no labels |
| 0.1.00018 | 25/11/2024 | create and assign labels to devices |
| 0.1.00017 | 25/11/2024 | fixed "Error removing device and entities:" |
| 0.1.00016 | 22/11/2024 | added new sensors to Omada Devices |
| 0.1.00015 | 22/11/2024 | fixed lower-/upper-case of device names |
| 0.1.00014 | 22/11/2024 | adjusted default interval to 30 seconds (was 5 minutes) |
| 0.1.00013 | 21/11/2024 | changed entity_id to match device type, device name and sensor name |
| 0.1.00012 | 19/11/2024 | fixing "Source Type" for URL Filtering |
| 0.1.00011 | 19/11/2024 | added sensors "Policy", "Source" and "Source Type" to URL Filterings |
| 0.1.00010 | 19/11/2024 | added translation type "SSID" to sensors "Source" and "Destination" |
| 0.1.00009 | 19/11/2024 | added translation type "IP Port Group", "IPv6 Group" and "IPv6 Port Group" to sensors "Source" and "Destination" |
| 0.1.00008 | 19/11/2024 | added translation type Network to sensors "Source" and "Destination" |
| 0.1.00007 | 19/11/2024 | added sensors "Source" and "Destination" to ACLS and translate type IPGroup |
| 0.1.00006 | 19/11/2024 | added sensors "Source Type" and "Destination Type" to ACLS |
| 0.1.00005 | 18/11/2024 | display correct names of Protocols in ACL Rules |
| 0.1.00004 | 18/11/2024 | ACL Rules and URL Filterings are automatically created and removed if needed while normal update process |
| 0.1.00003 | 18/11/2024 | ACL Rules and URL Filterings sensors are displayed again, removed Disabled switch again to prevent confusion |
| 0.1.00002 | 18/11/2024 | ACL Rules and URL Filterings are removed at integration reload if not available anymore |
| 0.1.00001 | 18/11/2024 | added DEvice Tracker for Omada Devices and Omada Clients |
| 0.0.5 | 17/11/2024 | fixing issues with creating / updating Omada Devices and Omada Clients |
| 0.0.4 | 05/11/2024 | acl / url filtering switch names |
| 0.0.3 | 05/11/2024 | restructured for HACS installation |
| 0.0.2 | 05/11/2024 | added clients |
| 0.0.1 | 04/11/2024 | initial version |
