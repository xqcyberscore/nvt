# OpenVAS Vulnerability Test
# $Id: stronghold.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Redhat Stronghold File System Disclosure
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
# Changes by rd: re-wrote the code to do pattern matching
#
# Copyright:
# Copyright (C) 2001 Felix Huber
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "Redhat Stronghold Secure Server File System Disclosure Vulnerability

The problem:
In Redhat Stronghold from versions 2.3 up to 3.0 a flaw exists that
allows a remote attacker to disclose sensitive system files including
the httpd.conf file, if a restricted access to the server status
report is not enabled when using those features.
This may assist an attacker in performing further attacks.

By trying the following urls, an attacker can gather sensitive
information:
http://target/stronghold-info will give information on configuration
http://target/stronghold-status will return among other information
the list of request made

Please note that this attack can be performed after a default
installation. The vulnerability seems to affect all previous version
of Stronghold.

Vendor status:
Patch was released (November 19, 2001)";

# v. 1.00 (last update 23.11.01)

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10803");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-0868");
 script_bugtraq_id(3577);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "Redhat Stronghold File System Disclosure";
 script_name(name);




 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");


 script_copyright("This script is Copyright (C) 2001 Felix Huber");
 family = "Web application abuses";
 script_family(family);
 script_dependencies( "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 req = http_get(item:"/stronghold-info", port:port);
 r   = http_keepalive_send_recv(port:port, data:req);
 if (! r ) exit(0);
 if("Stronghold Server Information" >< r)
 {
   security_message(port);
   exit(0);
 }

  req = http_get(item:"/stronghold-status", port:port);
  r   = http_keepalive_send_recv(port:port, data:req);
  if("Stronghold Server Status for" >< r)security_message(port);
}
