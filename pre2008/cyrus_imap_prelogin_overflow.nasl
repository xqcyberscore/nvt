# OpenVAS Vulnerability Test
# $Id: cyrus_imap_prelogin_overflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Cyrus IMAP pre-login buffer overrun
#
# Authors:
# Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Paul Johnston, Westpoint Ltd
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

tag_summary = "According to its banner, the remote Cyrus IMAP 
server is vulnerable to a pre-login buffer overrun. 
 
An attacker without a valid login could exploit this, and would be 
able to execute arbitrary commands as the owner of the Cyrus 
process. This would allow full access to all users' mailboxes.

More information : http://online.securityfocus.com/archive/1/301864";

tag_solution = "If possible, upgrade to an unaffected version. However, at
the time of writing no official fix was available. There is a source 
patch against 2.1.10 in the Bugtraq report.";

if(description)
{
 script_id(11196);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  
 name = "Cyrus IMAP pre-login buffer overrun";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("This script is Copyright (C) 2002 Paul Johnston, Westpoint Ltd");
 script_family("Gain a shell remotely");

 script_dependencies("find_service.nasl");	       		     
 script_require_ports("Services/imap", 143);

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.11196";
SCRIPT_DESC = "Cyrus IMAP pre-login buffer overrun";

port = get_kb_item("Services/imap");
if(!port) port = 143;

key = string("imap/banner/", port);
banner = get_kb_item(key);
if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(soc)
    { 
      banner = recv_line(socket:soc, length:255);
      close(soc);
    }
  }
}
if(!banner) exit(0);

if (("Cyrus IMAP4" >< banner) && egrep (pattern:"^\* OK.*Cyrus IMAP4 v([0-9]+\.[0-9]+\.[0-9]+.*) server ready", string:banner))
{
  version = ereg_replace(pattern:".* v(.*) server.*", string:banner, replace:"\1");
  set_kb_item (name:"imap/" + port + "/Cyrus", value:version);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value: version, exp:"^([0-9.]+)",base:"cpe:/a:cmu:cyrus_imap_server:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  if(egrep(pattern:"^(1\.*|2\.0\.*|2\.1\.[1-9][^0-9]|2\.1\.10)[0-9]*$", string:version))
  {
    security_message(port);
  }    
} 
