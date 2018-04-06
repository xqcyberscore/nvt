# OpenVAS Vulnerability Test
# $Id: flexwatch_auth_bypass.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: FlexWATCH Authentication Bypassing
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

tag_summary = "There is a vulnerability in the current version of FlexWATCH that allows an 
attacker to access administrative sections without being required to 
authenticate.

An attacker may use this flaw to gain the list of user accounts on this system
and the ability to reconfigure this service.

This is done by adding an additional '/' at the beginning of the URL.";

tag_solution = "None at this time - filter incoming traffic to this port";

# From: "Rafel Ivgi, The-Insider" <theinsider@012.net.il>
# Subject: FlexWATCH-Webs 2.2 (NTSC) Authorization Bypass
# Date: 2004-02-24 16:45

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12078");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1160");
  script_bugtraq_id(8942);
  script_xref(name:"OSVDB", value:"2842");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  name = "FlexWATCH Authentication Bypassing";
  script_name(name);
 

 
  summary = "Detect FlexWATCH Authentication Bypassing";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
 
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

  family = "General";
  script_family(family);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


req = http_get(item:"//admin/aindex.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
find = string("GoAhead-Webs");
find2 = string("admin.htm");
find3 = string("videocfg.htm");
if ( find >< res && find2 >< res && find3 >< res )
{
  security_message(port);
  exit(0);
}

