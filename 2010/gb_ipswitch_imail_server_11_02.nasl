###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipswitch_imail_server_11_02.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# Ipswitch IMail Server < 11.02 multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Ipswitch IMail Server < 11.02  is prone to multiple Vulnerabilities.

1. 
iMultiple buffer-overflow Vulnerabilities because it fails to perform adequate
boundary checks on user- supplied data.

2.
Multiple remote code-execution vulnerabilities.

An attacker can exploit these issues to execute arbitrary code with
SYSTEM-level privileges. Successfully exploiting these issues will
result in the complete compromise of affected computers. Failed
exploit attempts will result in a denial-of-service condition. 
Ipswitch IMail Server versions prior to 11.02 are vulnerable.";

tag_solution = "Vendor updates are available. Please contact the vendor for more
information.";

if (description)
{
 script_id(100718);
 script_version("$Revision: 5306 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-07-16 12:38:11 +0200 (Fri, 16 Jul 2010)");
 script_bugtraq_id(41719,41718,41717);
 script_tag(name:"cvss_base", value:"9.7");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
 script_name("Ipswitch IMail Server < 11.02 multiple Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41719");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41718");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41717");
 script_xref(name : "URL" , value : "http://www.ipswitch.com/Products/IMail_Server/index.html");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-10-127/");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp","Services/pop3","Services/imap",25, 110, 143);

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("smtp_func.inc");
include("pop3_func.inc");
include("imap_func.inc");
include("version_func.inc");

function check_vuln(banner,port) {
  version = eregmatch(pattern: "IMail ([0-9.]+)", string: banner);
  if(!isnull(version[1])) {
   if(version_is_less(version: version[1], test_version:"11.02")) {
     security_message(port:port);
     return TRUE;
   }  
  }  
}  

port = get_kb_item("Services/smtp");
if(!port) port = 25;
if(banner = get_smtp_banner(port:port)) {
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }  
}

port = get_kb_item("Services/pop3");
if(!port) port = 110;
if(banner = get_pop3_banner(port:port)) {
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }
}

port = get_kb_item("Services/imap");
if(!port) port = 143;
if(banner = get_imap_banner(port:port)) {
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }  
}

exit(0);

