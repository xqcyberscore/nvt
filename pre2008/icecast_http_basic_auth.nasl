# OpenVAS Vulnerability Test
# $Id: icecast_http_basic_auth.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: ICECast HTTP basic authorization DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote server runs ICECast 2.0.0, an open source streaming audio 
server.

This version is affected by a remote denial of service.

An remote attacker could send specially crafted URL, with a long string
passed in an Authorization header that will result in a loss of availability 
for the service.

*** OpenVAS reports this vulnerability using only
*** information that was gathered.";

tag_solution = "Upgrade to a newer version.";

#  Ref: ned <nd@felinemenace.org>

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.15397");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2027");
 script_bugtraq_id(10311);
 script_xref(name:"OSVDB", value:"6075");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 
 name = "ICECast HTTP basic authorization DoS";
 script_name(name);
 


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Denial of Service");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("icecast/banner");
 script_require_ports("Services/www", 8000);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:8000);
if(!port) exit(0);

banner = tolower(get_http_banner(port:port));
if (! banner ) exit(0);
if("icecast/" >< banner && egrep(pattern:"icecast/2\.0\.0[^0-9])", string:banner))
      security_message(port);
