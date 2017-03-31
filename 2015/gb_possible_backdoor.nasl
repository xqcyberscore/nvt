###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_possible_backdoor.nasl 3373 2016-05-23 18:32:02Z jan $
#
# Possible Backdoor
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105238");
 script_version("$Revision: 3373 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-23 20:32:02 +0200 (Mon, 23 May 2016) $");
 script_tag(name:"creation_date", value:"2015-03-16 10:53:07 +0100 (Mon, 16 Mar 2015)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

 script_name("Possible Backdoor");
 script_summary("Look for potential backdoors");
 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_family("Malware");
 script_dependencies("find_service2.nasl");
 script_tag(name : "summary" , value : "Look for potential backdoors");
 script_mandatory_keys("possible/backdoor");
 exit(0);
}

include("global_settings.inc");

if( port = get_kb_item("possible/backdoor") )
{
  name = get_kb_item("backdoor/name");
  security_message(port:port, data:"A backdoor (" + name + ") seems to be running on this port\n");
  exit( 0 );
}

exit( 99 );
