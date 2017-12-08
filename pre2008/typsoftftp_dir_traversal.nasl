# OpenVAS Vulnerability Test
# $Id: typsoftftp_dir_traversal.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: TYPSoft directory traversal flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

tag_summary = "The remote host seems to be running TYPSoft FTP earlier than 0.97.5

This version is prone to directory traversal attacks.
An attacker could send specially crafted URL to view arbitrary 
files on the system.";

tag_solution = "Use a different FTP server or upgrade to the newest version";

# Ref: joetesta@hushmail.com and Kistler Ueli <iuk@gmx.ch>

if(description)
{
 script_id(14706);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2489);
 script_cve_id("CVE-2002-0558");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "TYPSoft directory traversal flaw";

 script_name(name);


 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "FTP";
 script_family(family);
 script_dependencies("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

banner = get_ftp_banner(port:port);
if( ! banner ) exit(0);
if(egrep(pattern:".*TYPSoft FTP Server (0\.8|0\.9[0-6][^0-9]|0\.97[^0-9]|0\.97\.[0-4][^0-9])", string:banner) )
    security_message(port);
