###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_dgn2200_n300_mult_vuln.nasl 35234 2014-02-18 11:02:48Z Feb$
#
# NetGear DGN2200 N300 Wireless Router Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804099";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6699 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 14:07:37 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-02-18 11:02:48 +0530 (Tue, 18 Feb 2014)");
  script_name("NetGear DGN2200 N300 Wireless Router Multiple Vulnerabilities");

  tag_summary =
"This host has NetGear DGN2200 N300 Wireless Router and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Send a HTTP GET request to restricted page and check whether it is able to
access or not.";

  tag_insight =
"Multiple flaws are due to,
- FTP Server not properly sanitizing user input, specifically absolute paths.
- Program not allowing users to completely disable the Wi-Fi Protected Setup
  (WPS) functionality.
- Web interface attempting to find new firmware on an FTP server every time an
  administrator logs in.
- UPnP Interface as HTTP requests to /Public_UPNP_C3 do not require multiple
  steps, explicit confirmation, or a unique token when performing certain
  sensitive actions.
- Input passed via the 'ping_IPAddr' parameter is not properly sanitized upon
  submission to the /ping.cgi script.
- Input passed via the 'hostname' parameter is not properly sanitized upon
  submission to the /dnslookup.cgi script.
- Program storing password information in plaintext in /etc/passwd.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary commands,
gain access to arbitrary files, and manipulate the device's settings.

Impact Level: System/Application";

  tag_affected =
"NetGear DGN2200 N300 Wireless Router Firmware Version 1.0.0.36-7.0.37";

  tag_solution =
"The vendor has discontinued this product, and therefore has no patch or
upgrade that mitigates this problem. It is recommended that an alternate
software package be used in its place.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/31617");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/125184");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2014/Feb/104");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("NETGEAR_DGN/banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable initialization
http_port = 0;
banner = "";

## Get http port
http_port = get_http_port(default:8080);

## Get Banner
banner = get_http_banner(port:http_port);

if(!banner || 'Basic realm="NETGEAR DGN' >!< banner)exit(0);

url = '/currentsetting.htm';

if(http_vuln_check(port:http_port, url:url, pattern:"Firmware",
   extra_check: make_list("RegionTag", "Region", "Model",
   "InternetConnectionStatus", "ParentalControlSupported")))
{
  security_message(port:http_port);
  exit(0);
}
